"""
Suraksha Saathi - Digital Arrest Scam Shield for Senior Citizens and Their Families
Hybrid system: rule-based scam-pattern engine (always on) + optional LLM analysis.
 
Run:  streamlit run app.py
"""
 
import html
import json
import os
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
 
import streamlit as st
 
# ----------------------------------------------------------------------------
# 1. SCAM PATTERN RULES (English + Hindi + Hinglish)
#    Each rule has plain keywords and optional regex "patterns".
# ----------------------------------------------------------------------------
RULES = {
    "arrest_threat": {
        "weight": 30,
        "en": "Threat of arrest, warrant or legal action",
        "hi": "गिरफ्तारी, वारंट या कानूनी कार्रवाई की धमकी",
        "keywords": [
            "arrest", "arrested", "digital arrest", "warrant", "custody", "jail",
            "legal action", "girftar", "case darj", "fir darj", "गिरफ्तार", "गिरफ्तारी", "वारंट",
            "डिजिटल अरेस्ट", "अरेस्ट", "हिरासत", "जेल",
        ],
        "patterns": [
            r"(case|fir)\s+(has\s+been\s+|is\s+)?(registered|filed|lodged)",
            r"registered\s+a\s+case",
            r"look-?out\s+notice",
            r"avoid\s+(an?\s+)?(fir|case|arrest|legal\s+action)",
            r"(result\s+in|lead\s+to)\s+(your\s+)?(arrest|jail|custody)",
            r"केस\s+दर्ज",
        ],
    },
    "authority": {
        "weight": 15,
        "en": "Claims to be police, CBI, customs or another authority",
        "hi": "पुलिस, CBI, कस्टम या किसी अधिकारी होने का दावा",
        "keywords": [
            "cbi", "police", "mumbai police", "cyber crime", "cybercrime", "cyber cell", "narcotics",
            "customs", "supreme court", "enforcement directorate", "trai", "inspector",
            "officer", "income tax", "task force", "crime branch", "ncb",
            "पुलिस", "सीबीआई", "कस्टम", "नारकोटिक्स", "साइबर क्राइम", "सुप्रीम कोर्ट",
            "इंस्पेक्टर", "अधिकारी",
        ],
        "patterns": [r"\bed\s+officer\b"],
    },
    "legal_claim": {
        "weight": 10,
        "en": "Claims your Aadhaar/SIM/parcel is linked to a crime",
        "hi": "आधार/सिम/पार्सल को अपराध से जोड़ने का दावा",
        "keywords": [
            "aadhaar", "aadhar", "sim card", "sim", "parcel", "drugs", "money laundering",
            "hawala", "illegal", "fedex", "dhl", "courier", "passport", "passports",
            "obscene", "आधार", "सिम", "पार्सल", "ड्रग्स", "मनी लॉन्ड्रिंग", "अवैध",
        ],
        "patterns": [r"linked\s+to\s+(a\s+)?(crime|case|fraud)"],
    },
    "secrecy": {
        "weight": 25,
        "en": "Tells you to keep it secret or not to hang up",
        "hi": "किसी को न बताने या कॉल न काटने का दबाव",
        "keywords": [
            "confidential", "sealed inquiry", "national security", "do not disconnect",
            "don't disconnect", "dont disconnect", "stay on the call", "stay on this call",
            "stay on the line", "keep this secret", "kisi ko mat batana", "kisi se mat kehna",
            "call cut mat", "mat kehna", "किसी को न बताएं", "किसी को मत बताना",
            "किसी को न बताना", "कॉल कट मत", "कॉल न काटें", "गोपनीय",
        ],
        "patterns": [
            r"(do not|don't|dont|never)\s+(speak|talk|tell|inform|discuss)\s+(about\s+this\s+|this\s+)?(to|with)?\s*"
            r"(anyone|anybody|your family|your relatives|family|relatives|others|dad|papa|mom|mummy|father|mother)",
            r"(do not|don't|dont)\s+share\s+this\s+with\s+(anyone|your family|family|others)",
            r"(do not|don't)\s+leave\s+(your\s+)?(house|home|room)",
        ],
    },
    "money": {
        "weight": 30,
        "en": "Asks you to transfer money / use a 'safe account'",
        "hi": "पैसे ट्रांसफर करने / 'सेफ अकाउंट' में डालने को कहना",
        "keywords": [
            "safe account", "rbi account", "verification fund", "send money", "paise transfer",
            "paise bhejo", "jurmana", "सेफ अकाउंट", "पैसे भेजें", "पैसे भेजिए", "पैसे ट्रांसफर", "रुपये जमा", "रुपए जमा", "पैसे जमा", "पैसे ट्रांसफर", "पैसे भेजें", "जुर्माना",
            "वेरिफिकेशन के लिए पैसे", "आरबीआई अकाउंट",
        ],
        "patterns": [
            r"transfer\s+(your\s+|the\s+|all\s+)?(available\s+)?(funds|money|amount|balance|savings)",
            r"(safe|secure|rbi|verification|government|supervision|escrow)\s+account",
            r"(pay|deposit)\s.{0,30}\b(fine|fees?|penalty|bail|charges|security\s+(amount|deposit))\b",
        ],
    },
    "payment_request": {
        "weight": 15,
        "en": "Pushes you to pay through UPI or an app",
        "hi": "UPI या ऐप से भुगतान करने का दबाव",
        "keywords": [
            "upi", "upi id", "gpay", "google pay", "phonepe", "paytm", "pay now", "pay rs",
            "pay the", "pay immediately", "qr code",
        ],
        "patterns": [],
    },
    "urgency": {
        "weight": 10,
        "en": "Creates urgency and panic",
        "hi": "जल्दबाज़ी और डर का माहौल बनाना",
        "keywords": [
            "immediately", "right now", "last warning", "final warning", "final notice",
            "last chance", "turant", "jaldi", "abhi", "तुरंत", "अभी", "आखिरी चेतावनी", "फौरन",
        ],
        "patterns": [
            r"urgent(ly)?",
            r"(within|in)\s+(\d+|one|two|an?|half\s+an?)\s*(minutes?|mins?|hours?|hrs?)\b",
            r"\d+\s*minute\s+(mein|me)\b",
        ],
    },
    "video_call": {
        "weight": 10,
        "en": "Insists on a video call (Skype/WhatsApp) as 'verification'",
        "hi": "वीडियो कॉल (स्काइप/व्हाट्सऐप) पर 'जांच' के नाम पर रोकना",
        "keywords": [
            "video call", "skype", "whatsapp video", "stay on camera", "वीडियो कॉल", "स्काइप",
        ],
        "patterns": [r"keep\s+(your\s+)?camera\s+on"],
    },
    "ivr_hook": {
        "weight": 15,
        "en": "Robot-call hook ('press 9 to speak to the officer')",
        "hi": "रोबोट कॉल का जाल ('9 दबाएं')",
        "keywords": [],
        "patterns": [r"press\s+\d\s+(to|for)\s+(speak|talk|connect|customer|officer)"],
    },
    "sensitive_info": {
        "weight": 20,
        "en": "Asks for OTP, PIN, CVV or passwords",
        "hi": "OTP, पिन, CVV या पासवर्ड मांगना",
        "keywords": [
            "otp", "pin", "cvv", "password", "aadhaar number", "card number",
            "ओटीपी", "पिन", "पासवर्ड", "कार्ड नंबर",
        ],
        "patterns": [],
    },
    "otp_request": {
        "weight": 20,
        "en": "Asks you to share or read out an OTP / PIN",
        "hi": "OTP / पिन बताने या शेयर करने को कहना",
        "keywords": [],
        "patterns": [
            r"(?<!not )(?<!n't )(?<!never )\b(share|send|tell|give|provide|read\s+out)\s.{0,25}\b(otp|pin|cvv|password)\b",
        ],
    },
    "service_threat": {
        "weight": 30,
        "en": "Threatens to cut off your SIM, account or electricity",
        "hi": "सिम, अकाउंट या बिजली बंद करने की धमकी",
        "keywords": ["बंद हो जाएगा", "कट जाएगा"],
        "patterns": [
            r"(electricity|power|connection|sim|number|account|card|service)\s+(will|is\s+going\s+to)\s+(be\s+)?"
            r"(cut|disconnected|blocked|suspended|closed|deactivated)",
            r"(account|sim|number|card)\s+(has\s+been|is)\s+(blocked|frozen|suspended)",
            r"block\s+ho\s+(jayega|jaayega|jaega)",
            r"(kat|band|bandh|block)\s+(ho\s+)?(jayega|jaayega|jaega|jayegi)",
            r"avoid\s+(deactivation|blocking|suspension|disconnection)",
        ],
    },
    "bait": {
        "weight": 30,
        "en": "Offers a prize, job or 'KYC update' as bait",
        "hi": "इनाम, नौकरी या 'KYC अपडेट' का लालच",
        "keywords": [
            "lottery", "lucky draw", "you have won", "you've won", "part time job",
            "part-time job", "work from home", "free gift", "लॉटरी", "इनाम जीता",
        ],
        "patterns": [
            r"earn\s+(rs\.?|₹)?\s*\d",
            # KYC wording alone is not treated as scam bait. A suspicious link,
            # threat, money demand or other pattern can still raise the score.
        ],
    },
    "phishing_link": {
        "weight": 15,
        "en": "Contains a suspicious link or asks you to click/download",
        "hi": "संदिग्ध लिंक, या क्लिक/डाउनलोड करने को कहना",
        "keywords": [],
        "patterns": [
            r"https?://\S+",
            r"\b(bit\.ly|tinyurl\.com|goo\.gl)/\S+",
            r"click\s+(on\s+)?(the\s+|this\s+|here)",
            r"download\s.{0,20}\b(apk|app)\b",
        ],
    },
}
 
# Phrases that show a message is *warning about* scams, not making threats.
AWARENESS = {
    "keywords": ["awareness", "जागरूकता"],
    "patterns": [
        r"\b(never|does\s+not|doesn't|will\s+not|won't|cannot|can't)\s+(ever\s+)?(ask|demand|request|arrest)",
        r"\b(beware|be\s+aware|stay\s+alert|stay\s+safe|do\s+not\s+fall\s+for|don't\s+fall\s+for)\b",
        r"how\s+to\s+(spot|identify|avoid|stay\s+safe|protect)",
        r"कभी.{0,15}नहीं\s+मांग",
        r"जैसा\s+कुछ\s+नहीं\s+होता",
        r"kaise\s+bach",
        r"se\s+bach(ein|na|ne|iye|ke)\b",
    ],
}
AWARENESS_FACTOR = 0.4
 
SEVERITY = {"SAFE": 0, "CAREFUL": 1, "SCAM": 2}
 
 
def _kw_pattern(keyword: str) -> str:
    """Word-boundary match for English words; plain match for Hindi."""
    escaped = re.escape(keyword)
    return rf"(?<!\w){escaped}(?!\w)" if keyword.isascii() else escaped
 
 
def _find_hits(lowered: str, rule: dict) -> list:
    hits = []
    for k in rule.get("keywords", []):
        m = re.search(_kw_pattern(k), lowered)
        if m:
            hits.append(m.group(0))
    for p in rule.get("patterns", []):
        for m in re.finditer(p, lowered):
            if m.group(0).strip():
                hits.append(m.group(0).strip())
    return hits
 
 
def rule_analyze(text: str) -> dict:
    """Return matched categories, matched phrases and a 0-100 risk score."""
    lowered = text.lower().replace("\u2019", "'").replace("\u2018", "'")
    categories, phrases = [], []
    score = 0
 
    for key, rule in RULES.items():
        hits = _find_hits(lowered, rule)
        if hits:
            categories.append(key)
            phrases.extend(hits)
            score += rule["weight"]
 
    # Combination bonuses: the classic digital-arrest patterns
    if "arrest_threat" in categories and "money" in categories:
        score += 20
    if "authority" in categories and "secrecy" in categories:
        score += 10
    if "secrecy" in categories and "money" in categories:
        score += 10
 
    score = min(score, 100)
 
    awareness = bool(_find_hits(lowered, AWARENESS))
    if awareness:
        score = int(score * AWARENESS_FACTOR)
 
    if score >= 60:
        verdict = "SCAM"
    elif score >= 30:
        verdict = "CAREFUL"
    else:
        verdict = "SAFE"
 
    return {
        "score": score,
        "verdict": verdict,
        "categories": categories,
        "keywords": phrases,
        "awareness": awareness,
    }
 
 
# ----------------------------------------------------------------------------
# 2. OPTIONAL LLM LAYER (works only if an API key is available)
# ----------------------------------------------------------------------------
def get_api_key():
    key = os.getenv("ANTHROPIC_API_KEY")
    if key:
        return key
    try:
        return st.secrets["ANTHROPIC_API_KEY"]
    except Exception:
        return None
 
 
def llm_analyze(text: str, lang: str):
    """Ask Claude for a second opinion. Returns dict or None on any failure."""
    key = get_api_key()
    if not key:
        return None
    try:
        import anthropic
 
        client = anthropic.Anthropic(api_key=key, timeout=8.0, max_retries=0)
        language = "simple Hindi (Devanagari)" if lang == "hi" else "simple English"
        prompt = f"""You are a scam-detection assistant protecting elderly people in India
from "digital arrest" fraud (fake CBI/police/customs officers on calls or video calls who
threaten arrest, demand secrecy and push victims to move money to a "safe account").
 
Analyze the message below. Real police and government agencies NEVER demand money,
OTPs or secrecy over a call or video call, and there is no such thing as "digital arrest".
If the message is only an awareness/warning message about scams, or an ordinary personal
message, the verdict should be SAFE.
 
Reply with ONLY a JSON object, no markdown, in this exact shape:
{{"verdict": "SCAM" or "CAREFUL" or "SAFE",
  "score": integer 0-100,
  "one_line": "one short sentence for an elderly person, in {language}",
  "reasons": ["up to 4 short reasons, in {language}"]}}
 
MESSAGE:
\"\"\"{text}\"\"\""""
        response = client.messages.create(
            model=os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5"),
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = "".join(b.text for b in response.content if getattr(b, "text", None))
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        data = json.loads(match.group(0))
        if data.get("verdict") not in SEVERITY:
            return None
        data["score"] = max(0, min(100, int(data.get("score", 0))))
        data["reasons"] = [str(x)[:180] for x in data.get("reasons", [])[:4] if isinstance(x, (str, int, float))]
        data["one_line"] = str(data.get("one_line", ""))[:240]
        return data
    except Exception:
        return None
 
 
# ----------------------------------------------------------------------------
# 3. SELF-TEST MESSAGES (labelled by the team; used by the Self-test tab)
#    Set A was used while tuning the rules. Set B was written afterwards.
# ----------------------------------------------------------------------------
TEST_A = [
    # --- scams ---
    ("This is Inspector Sharma from Mumbai Police and CBI. Your Aadhaar is linked to a money laundering case and a parcel with drugs was found. You are under digital arrest. Do not disconnect the video call and do not tell anyone. Transfer money to the RBI safe account immediately for verification or we will issue a warrant.", "SCAM"),
    ("Do NOT disconnect this call or speak to anyone - this is a sealed inquiry monitored by the CBI. A digital arrest warrant has been issued and will be sent to your WhatsApp shortly. To avoid immediate custody, you must verify your financial records. Transfer your available funds to the secure RBI verification account provided to you. Failure to comply will result in your arrest within 30 minutes.", "SCAM"),
    ("मैं मुंबई पुलिस से बोल रहा हूँ। आपके आधार से जुड़ा पार्सल पकड़ा गया है जिसमें ड्रग्स हैं। आप डिजिटल अरेस्ट में हैं। वीडियो कॉल मत काटिए और किसी को मत बताना। तुरंत सेफ अकाउंट में पैसे ट्रांसफर करें वरना गिरफ्तारी का वारंट निकलेगा।", "SCAM"),
    ("Main CBI officer bol raha hoon. Aapke Aadhaar se illegal parcel pakda gaya hai. Aap digital arrest mein hain. Kisi ko mat batana aur video call cut mat karna. Abhi safe account mein paise transfer karo warna warrant nikalega.", "SCAM"),
    ("Sir, we are calling from FedEx. A parcel in your name contains 5 passports and 3 SIM cards. Customs and Narcotics Bureau have registered a case. Connect to the Mumbai Police officer on Skype immediately. Do not share this with your family.", "SCAM"),
    ("Your mobile number will be disconnected in 2 hours as per TRAI. Press 9 to speak to the officer. Illegal activities were traced to your SIM.", "SCAM"),
    ("ED officer here. Your bank account is being used for hawala. A look-out notice has been issued. Stay on this call, do not leave your house, and transfer Rs 4 lakh to the government verification account to clear your name.", "SCAM"),
    ("Supreme Court has issued an arrest warrant against you in a money laundering case. To get a stay order, deposit a refundable security amount in the RBI account within one hour. Keep this confidential.", "SCAM"),
    ("यह सीबीआई ऑफिस से कॉल है। आपके खिलाफ मनी लॉन्ड्रिंग का केस दर्ज है। गिरफ्तारी से बचना है तो अभी वेरिफिकेशन के लिए पैसे ट्रांसफर करें और घर में किसी को न बताएं।", "SCAM"),
    ("Cyber crime police se bol rahe hain. Aapke number se obscene calls hui hain. Case darj ho gaya hai. 30 minute mein jurmana bharo warna jail hogi. Ye baat kisi se mat kehna.", "SCAM"),
    ("Dear customer, your SBI account will be blocked today. Update KYC immediately using this link: http://sbi-kyc-update.xyz", "SCAM"),
    ("Aapka SBI account kal block ho jayega. KYC update karne ke liye is link par click karein: http://sbi-update.xyz", "SCAM"),
    # --- suspicious / outside the digital-arrest focus: should warn ---
    ("Your electricity will be cut tonight. Pay the pending bill immediately on this UPI id to avoid disconnection.", "CAREFUL"),
    ("Congratulations! You are in our lucky draw. Claim your reward here: http://claim-reward.example", "CAREFUL"),
    ("Part time job: earn Rs 5000 daily working from home. Message us on Telegram.", "CAREFUL"),
    ("Mom this is your son from a new number. I had an accident and need Rs 50,000 urgently. Please don't tell dad. Send on this UPI id.", "CAREFUL"),
    ("Your parcel could not be delivered. Pay Rs 25 redelivery fee at http://india-post-track.xyz within 24 hours.", "CAREFUL"),
    ("Final notice: your electricity connection will be cut tonight at 9:30 pm unless you call the officer on this number.", "CAREFUL"),
    ("Someone on a call said police will arrest me unless I do what they say. What should I do?", "CAREFUL"),
    # --- normal / safe ---
    ("Hi Papa, I will reach home by 7 pm. Please keep dinner ready. Love you.", "SAFE"),
    ("Mom, I'm coming home late today, don't wait for dinner.", "SAFE"),
    ("Your OTP for login is 482913. Do not share it with anyone. -HDFC Bank", "SAFE"),
    ("Your Amazon order #4521 has been delivered. Rate your experience.", "SAFE"),
    ("Reminder: Your electricity bill of Rs 1,240 is due on 28 Oct. Pay via the official app before the due date.", "SAFE"),
    ("Beta, please send me your UPI id, I will transfer the dinner share.", "SAFE"),
    ("Doctor appointment confirmed for Monday 10 am at City Hospital. Please bring your Aadhaar card.", "SAFE"),
    ("Police and CBI never ask for money or secrecy on a call. If someone threatens you with digital arrest, hang up and call 1930.", "SAFE"),
    ("जागरूकता संदेश: डिजिटल अरेस्ट जैसा कुछ नहीं होता। पुलिस या सीबीआई वीडियो कॉल पर कभी पैसे नहीं मांगती। ऐसा कॉल आए तो 1930 पर शिकायत करें।", "SAFE"),
    ("Traffic update: heavy rain expected in Lucknow tomorrow. Carry an umbrella.", "SAFE"),
    ("Namaste uncle, kal subah 10 baje temple chalna hai. Taiyaar rehna.", "SAFE"),
    ("Your Aadhaar update request is received. It will be processed in 30 days. Track on the UIDAI website.", "SAFE"),
    ("Please call me urgently, Dadi is not feeling well.", "SAFE"),
    ("Meeting at 5 pm on video call today, link will be shared by Rohan.", "SAFE"),
    ("Your parcel will be delivered today between 4 and 6 pm. Please keep your phone on.", "SAFE"),
    ("Bank statement for September is ready. Log in to the official app to view it.", "SAFE"),
]
 
TEST_B = [
    ("Hello, I am calling from Delhi Crime Branch. A case of cheating has been registered against your PAN. You must remain on video call until an inspector verifies you. Do not inform your relatives, it may jeopardise the investigation. Deposit Rs 90,000 in the supervision account as a refundable guarantee.", "SCAM"),
    ("आपके नाम से एक पार्सल जब्त हुआ है जिसमें नशीले पदार्थ मिले हैं। नारकोटिक्स ब्यूरो आपको अभी वीडियो कॉल पर गिरफ्तार करेगा। जमानत के लिए तुरंत पैसे ट्रांसफर करें।", "SCAM"),
    ("Greetings from the Telecom Department. Your Aadhaar is misused in 17 illegal SIM cards. Your number is going to be blocked. Contact the cyber cell officer on WhatsApp video now to avoid FIR.", "SCAM"),
    ("Sir, this is SBI fraud team. Your card has been frozen due to suspicious activity. Share the OTP sent to your phone immediately to unfreeze.", "SCAM"),
    ("Dear sir, you have been selected for a work from home job. Daily income 3000. Join our Telegram group.", "CAREFUL"),
    ("We tried delivering your courier but the address was incomplete. Update details and pay Rs 30 here: http://courier-update.cc", "CAREFUL"),
    ("Dadaji, pension credit message: Rs 18,500 credited to your account on 1 Oct. Check balance on the official bank app.", "SAFE"),
    ("Don't forget the family dinner on Sunday. Uncle is coming from Kanpur.", "SAFE"),
    ("Awareness: scammers pretending to be police ask people to stay on video call and transfer money. Stay alert and call 1930.", "SAFE"),
    ("Your train ticket PNR 4521896 is confirmed. Coach B2, seat 34. Show ID at boarding.", "SAFE"),
    ("Please call the police station if you see anything suspicious near the temple, the officer said at the meeting.", "SAFE"),
    ("Hi, this is Ravi from the bank. Your KYC is already updated, no action needed.", "SAFE"),
]
 
TEST_C = [
    ("Namaskar, main Mumbai Cyber Cell se Inspector Verma. Aapke naam par ek FIR darj hai. Aapko ghar se bahar nahi jaana hai aur video call par rehna hai. Case band karwane ke liye 75,000 rupaye supervision account mein jama karein.", "SCAM"),
    ("This is a final notice from the Enforcement Directorate. A summons has been issued for hawala transactions from your account. Failing to join the video verification today will result in immediate arrest. Do not discuss this call with anyone.", "SCAM"),
    ("आपके बैंक खाते से संदिग्ध लेन-देन मिला है। अगर आप अभी अपना ओटीपी और कार्ड नंबर नहीं बताएंगे तो खाता बंद हो जाएगा।", "SCAM"),
    ("Congratulations, your number won Rs 25 lakh in the Jio lucky draw. To claim, pay Rs 5,000 processing fee on the UPI id below.", "SCAM"),
    ("Your SIM KYC has expired. Visit this link to avoid deactivation: http://kyc-sim-renew.in", "CAREFUL"),
    ("Sir, aapka electricity bill pending hai. Aaj raat 9:30 tak pay nahi kiya to connection kat jayega. Is number par call karein.", "CAREFUL"),
    ("Beta, bank wale ne bola KYC update ho gaya hai. Aaj mat jana.", "SAFE"),
    ("Hi Nana ji, please check the police verification form for the new tenant and send it by Friday.", "SAFE"),
    ("Your SBI Credit Card ending 4821 was used for Rs 1,250 at Big Bazaar on 22 Oct. If not you, call the number on the back of your card.", "SAFE"),
    ("Grandpa, I'm in a video call with my teacher now. I'll call you after 20 minutes.", "SAFE"),
    ("Kal society meeting mein cyber police aayegi aur batayegi ki digital arrest scam se kaise bachein. Sabko aana hai.", "SAFE"),
    ("Please don't tell Dadi about the surprise party. It's a secret till Sunday!", "SAFE"),
]
 
 
def run_self_test(cases):
    results = []
    for text, expected in cases:
        got = rule_analyze(text)["verdict"]
        results.append((text, expected, got))
    right = sum(1 for _, e, g in results if e == g)
    return right, len(results), [r for r in results if r[1] != r[2]]
 
 
# ----------------------------------------------------------------------------
# 4. TEXT CONTENT (Hindi + English)
# ----------------------------------------------------------------------------
T = {
    "en": {
        "title": "🛡️ Suraksha Saathi",
        "tagline": "Check any suspicious call or message. Get a calm second opinion in seconds.",
        "input_label": "Paste the message, or describe what the caller said:",
        "placeholder": "Example: This is CBI. Your Aadhaar is linked to a crime. Do not disconnect the video call...",
        "button": "Check Now",
        "samples": "Try an example:",
        "empty": "Please paste or type something first.",
        "score": "Risk score",
        "flags": "Why we think so",
        "highlight": "Suspicious phrases highlighted",
        "do_now": "What to do right now",
        "family": "Alert your family",
        "family_btn": "📲 Send alert on WhatsApp",
        "family_note": "Opens WhatsApp with a ready message. You choose who to send it to.",
        "report": "Save evidence",
        "report_btn": "📄 Download report for 1930 / cybercrime.gov.in",
        "report_note": "A short summary you can show to the police or upload with your complaint.",
        "awareness_note": "This looks like a warning/awareness message about scams, so the score was lowered.",
        "ai_on": "AI + rule check used",
        "ai_off": "Rule check used (add an API key to enable AI analysis)",
        "verdict": {
            "SCAM": ("🔴 THIS IS A SCAM", "Real police or CBI never ask for money or secrecy on a call."),
            "CAREFUL": ("🟡 BE CAREFUL", "This has warning signs. Do not act. Check with family first."),
            "SAFE": ("🟢 NO MAJOR DANGER SEEN", "Still, never share OTP, PIN or send money to someone you don't know."),
        },
        "actions": [
            "Hang up. Do not stay on the video call.",
            "Do NOT send any money or share OTP, PIN or Aadhaar details.",
            "Remember: there is NO such thing as 'digital arrest' in Indian law.",
            "Call the cybercrime helpline **1930** immediately.",
            "Report at **cybercrime.gov.in** and save screenshots and numbers.",
            "Tell a family member or a trusted friend now.",
        ],
        "family_msg": "I received a suspicious call/message that looks like a scam. Please call me before I do anything. Message was: ",
        "tab_check": "🔍 Check",
        "tab_learn": "📚 Know the 5 signs",
        "tab_test": "🧪 Self-test",
        "learn_title": "5 signs of a digital arrest scam",
        "learn": [
            ("1. Fear of arrest", "They say you or your Aadhaar/SIM/parcel is linked to a crime."),
            ("2. 'Don't tell anyone'", "Scammers isolate you so no one can stop you."),
            ("3. 'Stay on the video call'", "They keep you on camera so you cannot think or call anyone."),
            ("4. 'Move money to a safe account'", "No real agency ever asks for this."),
            ("5. Extreme urgency", "'Within 30 minutes!' is meant to make you panic."),
        ],
        "golden": "**Golden rule:** Police and CBI do not arrest anyone over video call, and they never ask for money. Hang up and call **1930**.",
        "test_title": "How well does the checker work?",
        "test_note": "We ran the rule engine on messages written by our own team. This is a small self-check, **not an independent benchmark**. Rounds 2 and 3 were fresh messages written after the rules. We show the honest first-run score, then fixed the rules, so the scores now are *after* fixes.",
        "test_a": "Round 1 (written while building the rules)",
        "test_b": "Round 2 (fresh messages)",
        "test_c": "Round 3 (fresh messages)",
        "first_run": "First run, before fixes:",
        "test_correct": "correct",
        "test_misses": "Messages it got wrong:",
        "test_none": "No mistakes on this set.",
        "test_expected": "Expected",
        "test_got": "Got",
        "test_limit": "Limits: rules can miss rephrased scams, and the AI layer is optional. Always call 1930 if unsure.",
    },
    "hi": {
        "title": "🛡️ सुरक्षा साथी",
        "tagline": "कोई भी संदिग्ध कॉल या मैसेज चेक करें। कुछ ही सेकंड में सही सलाह पाएं।",
        "input_label": "मैसेज यहाँ पेस्ट करें, या बताएं कि कॉल करने वाले ने क्या कहा:",
        "placeholder": "उदाहरण: मैं CBI से बोल रहा हूँ। आपका आधार अपराध से जुड़ा है। वीडियो कॉल मत काटिए...",
        "button": "अभी जांचें",
        "samples": "उदाहरण आज़माएं:",
        "empty": "कृपया पहले कुछ लिखें या पेस्ट करें।",
        "score": "खतरे का स्कोर",
        "flags": "हमें ऐसा क्यों लगा",
        "highlight": "संदिग्ध शब्द हाइलाइट किए गए",
        "do_now": "अभी क्या करें",
        "family": "परिवार को बताएं",
        "family_btn": "📲 व्हाट्सऐप पर अलर्ट भेजें",
        "family_note": "व्हाट्सऐप में तैयार मैसेज खुलेगा। किसे भेजना है, आप चुनें।",
        "report": "सबूत सुरक्षित रखें",
        "report_btn": "📄 1930 / cybercrime.gov.in के लिए रिपोर्ट डाउनलोड करें",
        "report_note": "एक छोटी रिपोर्ट जो आप पुलिस को दिखा सकते हैं या शिकायत के साथ लगा सकते हैं।",
        "awareness_note": "यह स्कैम के बारे में चेतावनी/जागरूकता वाला मैसेज लग रहा है, इसलिए स्कोर कम किया गया।",
        "ai_on": "AI + नियम दोनों से जांच हुई",
        "ai_off": "नियमों से जांच हुई (AI के लिए API key जोड़ें)",
        "verdict": {
            "SCAM": ("🔴 यह स्कैम है!", "असली पुलिस या CBI कभी कॉल पर पैसे या गोपनीयता नहीं मांगती।"),
            "CAREFUL": ("🟡 सावधान रहें", "इसमें खतरे के संकेत हैं। कुछ न करें। पहले परिवार से पूछें।"),
            "SAFE": ("🟢 कोई बड़ा खतरा नहीं दिखा", "फिर भी अनजान को OTP, पिन या पैसे कभी न दें।"),
        },
        "actions": [
            "कॉल काट दें। वीडियो कॉल पर न रुकें।",
            "कोई पैसा न भेजें और OTP, पिन या आधार की जानकारी न दें।",
            "याद रखें: भारतीय कानून में 'डिजिटल अरेस्ट' जैसा कुछ नहीं होता।",
            "तुरंत साइबर क्राइम हेल्पलाइन **1930** पर कॉल करें।",
            "**cybercrime.gov.in** पर शिकायत करें और स्क्रीनशॉट व नंबर सुरक्षित रखें।",
            "अभी किसी परिवार वाले या भरोसेमंद व्यक्ति को बताएं।",
        ],
        "family_msg": "मुझे एक संदिग्ध कॉल/मैसेज आया है जो स्कैम लग रहा है। कुछ भी करने से पहले मुझे कॉल करें। मैसेज था: ",
        "tab_check": "🔍 जांचें",
        "tab_learn": "📚 5 पहचान जानें",
        "tab_test": "🧪 सेल्फ-टेस्ट",
        "learn_title": "डिजिटल अरेस्ट स्कैम की 5 पहचान",
        "learn": [
            ("1. गिरफ्तारी का डर", "वे कहते हैं कि आपका आधार/सिम/पार्सल किसी अपराध से जुड़ा है।"),
            ("2. 'किसी को मत बताना'", "ठग आपको अकेला कर देते हैं ताकि कोई रोक न सके।"),
            ("3. 'वीडियो कॉल पर बने रहिए'", "वे आपको कैमरे पर रखते हैं ताकि आप सोच न सकें।"),
            ("4. 'सेफ अकाउंट में पैसे डालिए'", "कोई असली एजेंसी ऐसा कभी नहीं कहती।"),
            ("5. बहुत जल्दबाज़ी", "'30 मिनट में!' कहकर डराया जाता है।"),
        ],
        "golden": "**सुनहरा नियम:** पुलिस और CBI वीडियो कॉल पर गिरफ्तारी नहीं करती और पैसे नहीं मांगती। कॉल काटें और **1930** पर फोन करें।",
        "test_title": "यह चेकर कितना सही काम करता है?",
        "test_note": "हमने नियमों को अपनी टीम के लिखे मैसेज पर चलाया। यह एक छोटी आंतरिक जांच है, **स्वतंत्र बेंचमार्क नहीं**। राउंड 2 और 3 के मैसेज नियमों के बाद लिखे गए। हमने पहली बार का असली स्कोर दिखाया, फिर नियम सुधारे, इसलिए अभी का स्कोर सुधार *के बाद* का है।",
        "test_a": "राउंड 1 (नियम बनाते समय लिखा)",
        "test_b": "राउंड 2 (नए मैसेज)",
        "test_c": "राउंड 3 (नए मैसेज)",
        "first_run": "पहली बार, सुधार से पहले:",
        "test_correct": "सही",
        "test_misses": "ये मैसेज यह गलत पहचान पाया:",
        "test_none": "इस सेट में कोई गलती नहीं।",
        "test_expected": "अपेक्षित",
        "test_got": "नतीजा",
        "test_limit": "सीमाएं: नियम बदले हुए शब्दों वाले स्कैम चूक सकते हैं, और AI वाला हिस्सा वैकल्पिक है। शक हो तो 1930 पर कॉल करें।",
    },
}
 
SAMPLES = {
    "SCAM": TEST_A[0][0],
    "SCAM_HI": TEST_A[2][0],
    "CAREFUL": TEST_A[12][0],
    "SAFE": TEST_A[19][0],
}
 
 
# ----------------------------------------------------------------------------
# 5. UI HELPERS
# ----------------------------------------------------------------------------
def combine(rule_result: dict, llm_result):
    """Final verdict = the more cautious of rules and AI. Returns (verdict, score)."""
    if not llm_result:
        return rule_result["verdict"], rule_result["score"]
    verdict = max([rule_result["verdict"], llm_result["verdict"]], key=lambda v: SEVERITY[v])
    score = max(rule_result["score"], llm_result["score"])
    return verdict, score
 
 
def get_analysis(text: str, lang: str) -> dict:
    """Analyse once per (text, language), with bounded optional AI use."""
    cache = st.session_state.setdefault("analysis_cache", {})
    key = (text, lang)
    if key not in cache:
        rule_result = rule_analyze(text)
        today = datetime.now().date().isoformat()
        if st.session_state.get("ai_limit_date") != today:
            st.session_state["ai_limit_date"] = today
            st.session_state["ai_calls_today"] = 0
        calls = int(st.session_state.get("ai_calls_today", 0))
        llm_result = None
        if calls < 10 and get_api_key():
            st.session_state["ai_calls_today"] = calls + 1
            llm_result = llm_analyze(text, lang)
        verdict, score = combine(rule_result, llm_result)
        cache[key] = {"rule": rule_result, "llm": llm_result, "verdict": verdict, "score": score}
    return cache[key]


def build_report(text: str, analysis: dict) -> str:
    """Plain-text evidence summary (always in English so officials can read it)."""
    ist = timezone(timedelta(hours=5, minutes=30))
    now = datetime.now(ist).strftime("%d %B %Y, %I:%M %p IST")
    rule = analysis["rule"]
    signs = [RULES[c]["en"] for c in rule["categories"]] or ["None found by the rule check"]
    phrases = sorted({p for p in rule["keywords"]}) or ["None"]
    lines = [
        "SURAKSHA SAATHI - SUSPICIOUS MESSAGE / CALL SUMMARY",
        "=" * 52,
        f"Generated: {now}",
        f"Result: {analysis['verdict']}  (risk score {analysis['score']}/100)",
        "",
        "WARNING SIGNS FOUND",
        *[f"  - {s}" for s in signs],
        "",
        "SUSPICIOUS PHRASES",
        "  " + ", ".join(phrases),
        "",
        "MESSAGE / WHAT THE CALLER SAID",
        text.strip(),
        "",
        "WHAT TO DO",
        "  1. Do not send money or share OTP, PIN or Aadhaar details.",
        "  2. Call the national cybercrime helpline 1930 right away.",
        "  3. Report at https://cybercrime.gov.in and keep screenshots,",
        "     phone numbers, UPI IDs and call times as evidence.",
        "",
        "Note: This is an automatic prototype summary, not an official",
        "document or a legal opinion. Add the caller's number, the time",
        "of the call and any payment details before filing a complaint.",
    ]
    return "\n".join(lines)
 
 
 
 
# ---- UI strings for the redesigned interface (added on top of the originals) ----
T["en"].update({
    "brand_sub": "Safer Seniors, Stronger India",
    "eyebrow": "Built for seniors and their families",
    "hero_h1": "Not sure about a call or message? Check before you act.",
    "hero_sub": "Paste what you received and get a calm second opinion in seconds, with clear next steps and a quick way to alert your family.",
    "trust": ["Hindi & English", "No sign-up needed", "Helpline 1930"],
    "card_title": "Check a message or call",
    "card_hint": "Paste the message, or write down what the caller said.",
    "ex_scam": "Scam example",
    "ex_susp": "Suspicious example",
    "ex_safe": "Normal example",
    "how_title": "How it works",
    "how": [
        ("Paste", "Add the message or describe the call."),
        ("Check", "We look for known scam patterns."),
        ("Act", "Follow the steps and alert your family."),
    ],
    "checking": "Checking the message...",
    "status": {
        "SCAM": ("High risk", "This looks like a scam"),
        "CAREFUL": ("Caution", "Be careful: warning signs found"),
        "SAFE": ("No obvious warning signs", "Nothing alarming found"),
    },
    "ai_chip_on": "AI + rules",
    "ai_chip_off": "Rule-based check",
    "gauge": "Risk score",
    "signs_title": "Why we think so",
    "no_signs": "No scam patterns were found in this text.",
    "msg_title": "Your message",
    "flagged": "Flagged phrases",
    "steps_title": "What to do now",
    "safe_title": "Stay careful anyway",
    "safe_tips": [
        "Never share your OTP, PIN or Aadhaar details with someone you don't know.",
        "Real police or CBI never ask for money over a call.",
        "If you are unsure, call **1930** or ask a family member first.",
    ],
    "family": "Alert your family",
    "family_desc": "Send a ready-made message so someone you trust can call you before you do anything.",
    "family_btn": "Send alert on WhatsApp",
    "report": "Save evidence",
    "report_desc": "Download a short summary to show the police or attach to your complaint.",
    "report_btn": "Download report",
    "learn_sub": "Scammers use the same tricks again and again. Learn to spot them.",
    "helpline_title": "Need help right now?",
    "helpline_body": "Call the national cybercrime helpline **1930**, or report at **cybercrime.gov.in**.",
    "footer": "Prototype built for the Hack India AI & Cybersecurity Hackathon. Not a substitute for official advice. Cybercrime helpline: 1930.",
})
T["hi"].update({
    "brand_sub": "बुज़ुर्ग सुरक्षित, परिवार निश्चिंत",
    "eyebrow": "बुज़ुर्गों और उनके परिवारों के लिए",
    "hero_h1": "कॉल या मैसेज पर शक है? कुछ करने से पहले जांचें।",
    "hero_sub": "जो मिला है उसे यहाँ डालें। कुछ ही सेकंड में शांत सलाह, साफ़ अगले कदम और परिवार को बताने का आसान तरीका पाएं।",
    "trust": ["हिन्दी और English", "साइन-अप की ज़रूरत नहीं", "हेल्पलाइन 1930"],
    "card_title": "मैसेज या कॉल जांचें",
    "card_hint": "मैसेज पेस्ट करें, या लिखें कि कॉल करने वाले ने क्या कहा।",
    "ex_scam": "स्कैम का उदाहरण",
    "ex_susp": "संदिग्ध उदाहरण",
    "ex_safe": "सामान्य उदाहरण",
    "how_title": "यह कैसे काम करता है",
    "how": [
        ("डालें", "मैसेज पेस्ट करें या कॉल के बारे में लिखें।"),
        ("जांचें", "हम जाने-पहचाने स्कैम पैटर्न खोजते हैं।"),
        ("कदम उठाएं", "बताए कदम अपनाएं और परिवार को खबर दें।"),
    ],
    "checking": "मैसेज जांचा जा रहा है...",
    "status": {
        "SCAM": ("ज़्यादा खतरा", "यह स्कैम लगता है"),
        "CAREFUL": ("सावधानी", "सावधान रहें: खतरे के संकेत मिले"),
        "SAFE": ("कोई साफ़ खतरा नहीं", "कुछ चिंताजनक नहीं मिला"),
    },
    "ai_chip_on": "AI + नियम",
    "ai_chip_off": "नियमों से जांच",
    "gauge": "खतरे का स्कोर",
    "signs_title": "हमें ऐसा क्यों लगा",
    "no_signs": "इस टेक्स्ट में कोई स्कैम पैटर्न नहीं मिला।",
    "msg_title": "आपका मैसेज",
    "flagged": "संदिग्ध शब्द",
    "steps_title": "अभी क्या करें",
    "safe_title": "फिर भी सावधान रहें",
    "safe_tips": [
        "अनजान व्यक्ति को OTP, पिन या आधार की जानकारी कभी न दें।",
        "असली पुलिस या CBI कभी कॉल पर पैसे नहीं मांगती।",
        "शक हो तो **1930** पर कॉल करें या पहले परिवार से पूछें।",
    ],
    "family": "परिवार को बताएं",
    "family_desc": "तैयार मैसेज भेजें ताकि कोई भरोसेमंद व्यक्ति आपके कुछ करने से पहले आपको कॉल कर सके।",
    "family_btn": "व्हाट्सऐप पर अलर्ट भेजें",
    "report": "सबूत सुरक्षित रखें",
    "report_desc": "एक छोटी रिपोर्ट डाउनलोड करें जो पुलिस को दिखा सकें या शिकायत के साथ लगा सकें।",
    "report_btn": "रिपोर्ट डाउनलोड करें",
    "learn_sub": "ठग बार-बार वही तरीके अपनाते हैं। इन्हें पहचानना सीखें।",
    "helpline_title": "अभी मदद चाहिए?",
    "helpline_body": "राष्ट्रीय साइबर क्राइम हेल्पलाइन **1930** पर कॉल करें, या **cybercrime.gov.in** पर शिकायत करें।",
    "footer": "यह हैक इंडिया AI और साइबर सिक्योरिटी हैकाथॉन के लिए बना प्रोटोटाइप है। यह आधिकारिक सलाह का विकल्प नहीं है। साइबर क्राइम हेल्पलाइन: 1930।",
})
T["en"].update({"tab_check": "Check", "tab_learn": "5 signs", "tab_test": "Self-test"})
T["hi"].update({"tab_check": "जांचें", "tab_learn": "5 पहचान", "tab_test": "सेल्फ-टेस्ट"})
T["en"]["empty"] = "Please paste or type a message first."
T["hi"]["empty"] = "कृपया पहले कोई मैसेज पेस्ट करें या लिखें।"

T["en"].update({
"tab_drill":"🎭 Scam Drill","text_size":"Text size","size_options":["Normal","Large","Extra large"],
"privacy_title":"How we protect your privacy","privacy_body":"Messages are used during your active session and are not saved to a database by this prototype. If optional AI analysis is enabled, message text is sent to Anthropic (Claude). Avoid entering passwords, OTPs or unnecessary personal details.",
"limits_title":"Limits of this tool","limits_body":"This prototype checks known patterns and may miss scams or flag genuine messages. A risk score is not the probability that a message is fraudulent. When in doubt, hang up and call 1930.",
"share_title":"Share this warning","share_btn":"Share warning on WhatsApp","share_note":"A ready-made warning opens in WhatsApp. Choose your family group before sending.",
"drill_title":"Practice: spot the scam","drill_intro":"Practice what to do during a suspicious call. Works without an API key.",
"scenario_label":"Choose a practice scenario","scenario_options":["Fake CBI officer","Fake parcel / SIM-block call"],
"step_label":"Practice step","choice_label":"What would you do?","next_step":"Next step","restart_drill":"Start again",
"drill_done":"Practice complete","drill_score":"Safe choices",
"drill_summary":"Golden rule: hang up, tell someone you trust, and call 1930 if money or financial details are at risk.",
"privacy_short":"Privacy and limitations"})
T["hi"].update({
"tab_drill":"🎭 स्कैम अभ्यास","text_size":"अक्षरों का आकार","size_options":["सामान्य","बड़ा","बहुत बड़ा"],
"privacy_title":"हम आपकी निजता कैसे सुरक्षित रखते हैं","privacy_body":"इस प्रोटोटाइप में मैसेज खुले सेशन के दौरान इस्तेमाल होता है और डेटाबेस में सेव नहीं किया जाता। अगर AI जांच चालू है, तो मैसेज का टेक्स्ट Anthropic (Claude) को भेजा जाता है। पासवर्ड, OTP या गैर-ज़रूरी निजी जानकारी न डालें।",
"limits_title":"इस टूल की सीमाएँ","limits_body":"यह प्रोटोटाइप जाने-पहचाने पैटर्न देखता है। कोई स्कैम छूट सकता है या सही मैसेज पर चेतावनी आ सकती है। स्कोर का मतलब स्कैम होने की संभावना नहीं है। शक हो तो कॉल काटें और 1930 पर कॉल करें।",
"share_title":"यह चेतावनी दूसरों को भेजें","share_btn":"व्हाट्सऐप पर चेतावनी भेजें","share_note":"व्हाट्सऐप में तैयार संदेश खुलेगा। भेजने से पहले परिवार का सही ग्रुप चुनें।",
"drill_title":"अभ्यास करें: स्कैम पहचानें","drill_intro":"संदिग्ध कॉल आने पर क्या करना है, इसका अभ्यास करें। AI key की ज़रूरत नहीं है।",
"scenario_label":"अभ्यास चुनें","scenario_options":["नकली CBI अधिकारी","नकली पार्सल / SIM बंद होने की कॉल"],
"step_label":"अभ्यास का चरण","choice_label":"आप क्या करेंगे?","next_step":"अगला चरण","restart_drill":"फिर से अभ्यास करें",
"drill_done":"अभ्यास पूरा हुआ","drill_score":"सुरक्षित फैसले",
"drill_summary":"याद रखें: कॉल काटें, भरोसेमंद व्यक्ति को बताएं, और पैसे या बैंक की जानकारी का खतरा हो तो 1930 पर कॉल करें।",
"privacy_short":"निजता और सीमाएँ"})


T["en"].update({
"tab_drill":"🎭 Scam Drill","text_size":"Text size","size_options":["Normal","Large","Extra large"],
"privacy_title":"How we protect your privacy","privacy_body":"Messages are used during your active session and are not saved to a database by this prototype. If optional AI analysis is enabled, message text is sent to Anthropic (Claude). Avoid entering passwords, OTPs or unnecessary personal details.",
"limits_title":"Limits of this tool","limits_body":"This prototype checks known patterns and may miss scams or flag genuine messages. A risk score is not the probability that a message is fraudulent. When in doubt, hang up and call 1930.",
"share_title":"Share this warning","share_btn":"Share warning on WhatsApp","share_note":"A ready-made warning opens in WhatsApp. Choose your family group before sending.",
"drill_title":"Practice: spot the scam","drill_intro":"Practice what to do during a suspicious call. Works without an API key.",
"scenario_label":"Choose a practice scenario","scenario_options":["Fake CBI officer","Fake parcel / SIM-block call"],
"step_label":"Practice step","choice_label":"What would you do?","next_step":"Next step","restart_drill":"Start again",
"drill_done":"Practice complete","drill_score":"Safe choices",
"drill_summary":"Golden rule: hang up, tell someone you trust, and call 1930 if money or financial details are at risk.",
"privacy_short":"Privacy and limitations"})
T["hi"].update({
"tab_drill":"🎭 स्कैम अभ्यास","text_size":"अक्षरों का आकार","size_options":["सामान्य","बड़ा","बहुत बड़ा"],
"privacy_title":"हम आपकी निजता कैसे सुरक्षित रखते हैं","privacy_body":"इस प्रोटोटाइप में मैसेज खुले सेशन के दौरान इस्तेमाल होता है और डेटाबेस में सेव नहीं किया जाता। अगर AI जांच चालू है, तो मैसेज का टेक्स्ट Anthropic (Claude) को भेजा जाता है। पासवर्ड, OTP या गैर-ज़रूरी निजी जानकारी न डालें।",
"limits_title":"इस टूल की सीमाएँ","limits_body":"यह प्रोटोटाइप जाने-पहचाने पैटर्न देखता है। कोई स्कैम छूट सकता है या सही मैसेज पर चेतावनी आ सकती है। स्कोर का मतलब स्कैम होने की संभावना नहीं है। शक हो तो कॉल काटें और 1930 पर कॉल करें।",
"share_title":"यह चेतावनी दूसरों को भेजें","share_btn":"व्हाट्सऐप पर चेतावनी भेजें","share_note":"व्हाट्सऐप में तैयार संदेश खुलेगा। भेजने से पहले परिवार का सही ग्रुप चुनें।",
"drill_title":"अभ्यास करें: स्कैम पहचानें","drill_intro":"संदिग्ध कॉल आने पर क्या करना है, इसका अभ्यास करें। AI key की ज़रूरत नहीं है।",
"scenario_label":"अभ्यास चुनें","scenario_options":["नकली CBI अधिकारी","नकली पार्सल / SIM बंद होने की कॉल"],
"step_label":"अभ्यास का चरण","choice_label":"आप क्या करेंगे?","next_step":"अगला चरण","restart_drill":"फिर से अभ्यास करें",
"drill_done":"अभ्यास पूरा हुआ","drill_score":"सुरक्षित फैसले",
"drill_summary":"याद रखें: कॉल काटें, भरोसेमंद व्यक्ति को बताएं, और पैसे या बैंक की जानकारी का खतरा हो तो 1930 पर कॉल करें।",
"privacy_short":"निजता और सीमाएँ"})

 
 
# ----------------------------------------------------------------------------
# 5b. DESIGN SYSTEM: theme, icons and small HTML components
# ----------------------------------------------------------------------------
COLORS = {"SCAM": "#F87171", "CAREFUL": "#FBBF24", "SAFE": "#34D399"}
 
THEME_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Noto+Sans+Devanagari:wght@400;500;600;700&display=swap');
:root{
  --ss-bg:#0B1220; --ss-bg-soft:#0E1627; --ss-card:#111C2E; --ss-elev:#172438;
  --ss-line:#223049; --ss-line-2:#2E4060;
  --ss-teal:#2DD4BF; --ss-teal-hi:#5EEAD4; --ss-teal-ink:#06201E;
  --ss-text:#F1F5F9; --ss-text-2:#B8C4D6; --ss-muted:#8EA0B9;
  --ss-red:#F87171; --ss-amber:#FBBF24; --ss-green:#34D399;
  --ss-font:'Inter','Noto Sans Devanagari',system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
}
/* ---------- app shell ---------- */
.stApp{background:var(--ss-bg)!important;color:var(--ss-text);font-family:var(--ss-font)!important}
.stApp p,.stApp label,.stApp li,.stApp button,.stApp textarea,.stApp input,.stApp a,.stApp summary,.stApp h1,.stApp h2,.stApp h3{font-family:var(--ss-font)!important}
[data-testid="stHeader"]{background:transparent!important}
[data-testid="stToolbar"],[data-testid="stDecoration"],#MainMenu,footer{display:none!important}
[data-testid="stMainBlockContainer"],.stMainBlockContainer,.block-container{max-width:1040px!important;padding:1.1rem 1.25rem 3rem!important}
[data-testid="stElementContainer"]:has(> [data-testid="stMarkdown"] style){display:none!important}
.ss,.ss *{box-sizing:border-box;font-family:var(--ss-font)}
.ss svg{flex:none}
@keyframes ss-rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){.ss,.ss *,.stApp *{animation:none!important;transition:none!important}}
.stButton>button,[data-testid="stDownloadButton"] button,[data-testid="stLinkButton"] a{min-height:44px!important}
button:focus-visible,input:focus-visible,textarea:focus-visible,a:focus-visible,[role="radio"]:focus-visible{outline:3px solid #5EEAD4!important;outline-offset:3px!important}
 
/* ---------- brand + hero ---------- */
.ss-topbar{display:flex;align-items:center;gap:12px;padding:6px 0}
.ss-logo{width:44px;height:44px;border-radius:13px;background:var(--ss-teal);display:grid;place-items:center;box-shadow:0 8px 22px rgba(45,212,191,.28)}
.ss-brand-name{font-weight:800;font-size:1.28rem;letter-spacing:-.015em;color:var(--ss-text);line-height:1.2}
.ss-brand-sub{font-size:.82rem;color:var(--ss-muted);line-height:1.35}
.ss-hero{padding:26px 0 10px;position:relative}
.ss-hero::after{content:"";position:absolute;right:8px;top:6px;width:230px;height:270px;background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 120 140' fill='none' stroke='%232DD4BF' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M60 6l48 18v33c0 29-20 54-48 77C32 111 12 86 12 57V24z' stroke-width='2' opacity='.38'/%3E%3Cpath d='M60 24l32 12v22c0 19-13 36-32 51C41 94 28 77 28 58V36z' stroke-width='1.5' opacity='.24'/%3E%3Cpath d='M44 62l12 12 22-24' stroke-width='4' opacity='.55'/%3E%3C/svg%3E") no-repeat center/contain;pointer-events:none}
@media (max-width:1100px){.ss-hero::after{display:none}}
.ss-eyebrow{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border-radius:999px;background:rgba(45,212,191,.10);border:1px solid rgba(45,212,191,.30);color:var(--ss-teal);font-size:.8rem;font-weight:600}
.ss-hero h1{font-size:clamp(1.65rem,3.6vw,2.5rem);line-height:1.18;font-weight:800;letter-spacing:-.02em;margin:14px 0 10px;color:var(--ss-text);max-width:760px;padding:0}
.ss-hero p{font-size:1.04rem;line-height:1.65;color:var(--ss-text-2);max-width:660px;margin:0}
.ss-trust{display:flex;flex-wrap:wrap;gap:10px;margin-top:18px}
.ss-trust span{display:inline-flex;align-items:center;gap:8px;padding:8px 13px;border-radius:10px;background:var(--ss-card);border:1px solid var(--ss-line);color:var(--ss-text-2);font-size:.87rem;font-weight:500}
.ss-trust svg{color:var(--ss-teal)}
 
/* ---------- cards ---------- */
.ss-card{background:var(--ss-card);border:1px solid var(--ss-line);border-radius:18px;padding:20px 22px;box-shadow:0 10px 30px rgba(2,6,15,.35);transition:border-color .15s ease}
.ss-card:hover{border-color:var(--ss-line-2)}
.ss-card h3,.ss-act h3{margin:0 0 12px;padding:0;font-size:1.02rem;font-weight:700;color:var(--ss-text);display:flex;align-items:center;gap:10px;line-height:1.3}
.ss-h-ico{width:30px;height:30px;border-radius:9px;background:var(--ss-elev);display:inline-grid;place-items:center;color:var(--ss-teal);flex:none}
.ss-sub{color:var(--ss-text-2);font-size:.95rem;line-height:1.6;margin:0}
.ss-muted{color:var(--ss-muted);font-size:.85rem;line-height:1.55}
.ss-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:16px;margin-top:16px;animation:ss-rise .3s ease both}
.ss-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 11px;border-radius:999px;font-size:.78rem;font-weight:700;letter-spacing:.01em;background:rgba(45,212,191,.12);color:var(--ss-teal);border:1px solid rgba(45,212,191,.3)}
.ss-chip-muted{background:var(--ss-elev);color:var(--ss-text-2);border-color:var(--ss-line-2);font-weight:600}
.ss-v-SCAM{--c:#F87171;--c-rgb:248,113,113}
.ss-v-CAREFUL{--c:#FBBF24;--c-rgb:251,191,36}
.ss-status.ss-v-CAREFUL{background:linear-gradient(rgba(251,191,36,.10),rgba(251,191,36,.10)),var(--ss-card)}
.ss-v-SAFE{--c:#34D399;--c-rgb:52,211,153}
.ss-v-SCAM .ss-chip,.ss-v-CAREFUL .ss-chip,.ss-v-SAFE .ss-chip{background:rgba(var(--c-rgb),.14);color:var(--c);border-color:rgba(var(--c-rgb),.38)}
 
/* ---------- results ---------- */
.ss-status{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;margin-top:18px;padding:22px 24px;border-radius:18px;border:1px solid rgba(var(--c-rgb),.35);border-left:5px solid var(--c);background:linear-gradient(rgba(var(--c-rgb),.07),rgba(var(--c-rgb),.07)),var(--ss-card);box-shadow:0 10px 30px rgba(2,6,15,.35);animation:ss-rise .3s ease both}
.ss-status-main{display:flex;align-items:center;gap:18px;flex:1 1 340px;min-width:0}
.ss-status-ico{width:56px;height:56px;border-radius:16px;background:rgba(var(--c-rgb),.15);color:var(--c);display:grid;place-items:center;flex:none}
.ss-status-title{margin:8px 0 4px;padding:0;font-size:1.45rem;line-height:1.25;font-weight:800;letter-spacing:-.01em;color:var(--ss-text)}
.ss-status-line{margin:0;color:var(--ss-text-2);font-size:1rem;line-height:1.55}
.ss-meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.ss-gauge{display:flex;flex-direction:column;align-items:center;gap:4px;margin:0 6px}
.ss-gauge-label{font-size:.78rem;color:var(--ss-muted);font-weight:600}
.ss-signs,.ss-steps{list-style:none;margin:0;padding:0}
.ss-signs{display:flex;flex-direction:column;gap:10px}
.ss-signs li{display:flex;gap:12px;align-items:flex-start;padding:11px 13px;border-radius:12px;background:var(--ss-elev);color:var(--ss-text);font-size:.96rem;line-height:1.5}
.ss-signs li svg{margin-top:2px;color:var(--c,var(--ss-amber))}
.ss-signs li.ss-ok svg{color:var(--ss-green)}
.ss-msg{background:var(--ss-bg-soft);border:1px solid var(--ss-line);border-radius:12px;padding:14px 16px;font-size:.98rem;line-height:1.75;color:var(--ss-text);word-break:break-word;max-height:300px;overflow:auto}
.ss-msg mark{background:rgba(251,191,36,.20);color:#FDE68A;padding:1px 5px;border-radius:5px;border-bottom:2px solid var(--ss-amber)}
.ss-phrases{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.ss-phr{display:inline-block;padding:4px 11px;border-radius:999px;background:rgba(251,191,36,.12);border:1px solid rgba(251,191,36,.35);color:#FDE68A;font-size:.82rem;font-weight:500}
.ss-label{font-size:.78rem;font-weight:700;color:var(--ss-muted);letter-spacing:.04em;margin:14px 0 0}
.ss-steps{counter-reset:s;display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:10px}
.ss-steps li{counter-increment:s;display:flex;gap:14px;align-items:flex-start;padding:12px 14px;border-radius:12px;background:var(--ss-elev);color:var(--ss-text);line-height:1.55;font-size:.97rem}
.ss-steps li::before{content:counter(s);flex:none;width:26px;height:26px;border-radius:50%;background:var(--ss-teal);color:var(--ss-teal-ink);font-weight:800;font-size:.85rem;display:grid;place-items:center;margin-top:1px}
.ss-steps strong,.ss-callout strong{color:var(--ss-teal)}
.ss-note{display:flex;gap:10px;align-items:flex-start;padding:11px 13px;border-radius:12px;font-size:.9rem;line-height:1.55;margin-top:12px}
.ss-note-info{background:rgba(45,212,191,.08);border:1px solid rgba(45,212,191,.28);color:#CFFAF3}
.ss-note-warn{background:rgba(251,191,36,.10);border:1px solid rgba(251,191,36,.35);color:#FDE68A}
.ss-note svg{margin-top:2px}
 
/* ---------- how it works / learn / self-test ---------- */
.ss-how{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,230px),1fr));gap:14px;margin-top:18px}
.ss-how-item{display:flex;gap:13px;padding:15px 16px;border-radius:14px;background:var(--ss-card);border:1px solid var(--ss-line)}
.ss-how-n{width:30px;height:30px;border-radius:50%;background:rgba(45,212,191,.12);border:1px solid rgba(45,212,191,.35);color:var(--ss-teal);display:grid;place-items:center;font-weight:800;font-size:.9rem;flex:none}
.ss-how-t{font-weight:700;color:var(--ss-text);font-size:.98rem;margin-bottom:2px}
.ss-how-d{color:var(--ss-text-2);font-size:.9rem;line-height:1.5}
.ss-section-title{font-size:1.35rem;font-weight:800;letter-spacing:-.01em;color:var(--ss-text);margin:6px 0 6px;padding:0}
.ss-learn{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,290px),1fr));gap:16px;margin-top:18px}
.ss-learn-card{display:flex;gap:16px;align-items:flex-start}
.ss-help{background:rgba(45,212,191,.08);border-color:rgba(45,212,191,.30)}
.ss-help .ss-learn-n{background:rgba(45,212,191,.14)}
.ss-help strong{color:var(--ss-teal)}
.ss-learn-n{width:40px;height:40px;border-radius:12px;background:var(--ss-elev);border:1px solid var(--ss-line-2);color:var(--ss-teal);display:grid;place-items:center;font-weight:800;font-size:1.1rem;flex:none}
.ss-learn-t{font-weight:700;color:var(--ss-text);font-size:1.02rem;margin-bottom:4px;line-height:1.35}
.ss-callout{display:flex;gap:14px;align-items:flex-start;margin-top:16px;padding:18px 20px;border-radius:16px;background:rgba(45,212,191,.08);border:1px solid rgba(45,212,191,.30);color:var(--ss-text);line-height:1.6}
.ss-callout svg{color:var(--ss-teal);margin-top:2px}
.ss-big{font-size:2.1rem;font-weight:800;letter-spacing:-.02em;color:var(--ss-text);line-height:1.1}
.ss-big span{font-size:1rem;font-weight:600;color:var(--ss-muted);margin-left:4px}
.ss-bar{height:8px;border-radius:99px;background:var(--ss-line);margin:14px 0 12px;overflow:hidden}
.ss-bar i{display:block;height:100%;border-radius:99px;background:var(--ss-teal)}
.ss-test-top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.ss-test-label{font-size:.9rem;font-weight:600;color:var(--ss-text-2);margin-bottom:6px}
.ss-details{margin-top:12px}
.ss-details summary{cursor:pointer;color:var(--ss-text-2);font-size:.9rem;font-weight:600;padding:6px 0}
.ss-details summary:hover{color:var(--ss-teal)}
.ss-details summary:focus-visible{outline:2px solid var(--ss-teal);outline-offset:2px;border-radius:6px}
.ss-details ul{margin:8px 0 0;padding:0;list-style:none;display:flex;flex-direction:column;gap:8px}
.ss-details li{padding:10px 12px;border-radius:10px;background:var(--ss-elev);font-size:.88rem;line-height:1.5;color:var(--ss-text-2)}
.ss-details li b{color:var(--ss-text)}
.ss-foot{border-top:1px solid var(--ss-line);margin-top:34px;padding-top:16px;color:var(--ss-muted);font-size:.82rem;line-height:1.65}
 
/* ---------- Streamlit widgets (scoped to what this app uses) ---------- */
[data-testid="stRadio"]{display:flex;justify-content:flex-end}
[data-testid="stRadio"] [role="radiogroup"]{background:var(--ss-card);border:1px solid var(--ss-line);border-radius:12px;padding:4px;gap:4px!important;display:inline-flex!important;flex-direction:row!important;width:fit-content}
[data-testid="stRadio"] label[data-baseweb="radio"]{margin:0!important;padding:6px 15px!important;border-radius:9px;cursor:pointer;color:var(--ss-text-2);transition:background .15s,color .15s}
[data-testid="stRadio"] label[data-baseweb="radio"] > div:first-of-type:not(:has(p)){display:none!important}
[data-testid="stRadio"] label[data-baseweb="radio"] p{margin:0;font-weight:600;font-size:.92rem;color:inherit!important}
[data-testid="stRadio"] label[data-baseweb="radio"]:hover{background:rgba(255,255,255,.06);color:var(--ss-text)}
[data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked){background:var(--ss-teal);color:var(--ss-teal-ink)}
[data-testid="stRadio"] label[data-baseweb="radio"]:has(input:focus-visible){outline:2px solid var(--ss-teal);outline-offset:2px}
 
[data-baseweb="tab-list"]{gap:6px!important;background:var(--ss-card);border:1px solid var(--ss-line);border-radius:14px;padding:5px;width:fit-content;max-width:100%;overflow-x:auto}
button[data-baseweb="tab"]{height:auto!important;padding:9px 18px!important;border-radius:10px!important;color:var(--ss-text-2)!important;background:transparent!important;transition:background .15s,color .15s}
button[data-baseweb="tab"] p{font-size:.95rem!important;font-weight:600!important;margin:0;color:inherit!important}
button[data-baseweb="tab"]:hover{color:var(--ss-text)!important;background:rgba(255,255,255,.05)!important}
button[data-baseweb="tab"][aria-selected="true"]{background:var(--ss-elev)!important;color:var(--ss-teal)!important;box-shadow:inset 0 0 0 1px var(--ss-line-2)}
button[data-baseweb="tab"]:focus-visible{outline:2px solid var(--ss-teal)!important;outline-offset:2px}
[data-baseweb="tab-highlight"],[data-baseweb="tab-border"]{display:none!important}
[data-baseweb="tab-panel"]{padding-top:1.1rem!important}
 
.st-key-input_card,.st-key-family_card,.st-key-report_card{box-sizing:border-box;background:var(--ss-card);border:1px solid var(--ss-line);border-radius:18px;padding:20px 22px;box-shadow:0 10px 30px rgba(2,6,15,.35)}
.st-key-family_card,.st-key-report_card{height:100%}
[data-testid="stTextArea"] [data-baseweb="textarea"],[data-testid="stTextArea"] [data-baseweb="base-input"]{background:var(--ss-bg-soft)!important;border:1px solid var(--ss-line-2)!important;border-radius:12px!important;transition:border-color .15s,box-shadow .15s}
[data-testid="stTextArea"] [data-baseweb="textarea"]:focus-within,[data-testid="stTextArea"] [data-baseweb="base-input"]:focus-within{border-color:var(--ss-teal)!important;box-shadow:0 0 0 3px rgba(45,212,191,.22)!important}
[data-testid="stTextArea"] textarea{background:transparent!important;color:var(--ss-text)!important;font-size:1.05rem!important;line-height:1.65!important;padding:14px 16px!important;caret-color:var(--ss-teal)}
[data-testid="stTextArea"] textarea::placeholder{color:var(--ss-muted)!important;opacity:1}
[data-testid="InputInstructions"]{color:var(--ss-muted)!important}
 
.stApp [data-testid="stBaseButton-secondary"],.stApp button[kind="secondary"],.stApp [data-testid="stDownloadButton"] button,.stApp a[data-testid="stBaseLinkButton-secondary"],.stApp [data-testid="stLinkButton"] a{background:var(--ss-elev)!important;color:var(--ss-text)!important;border:1px solid var(--ss-line-2)!important;border-radius:12px!important;padding:.55rem 1.15rem!important;min-height:2.8rem;font-weight:600!important;text-decoration:none!important;display:inline-flex;align-items:center;justify-content:center;gap:8px;transition:border-color .15s,background .15s,box-shadow .15s}
.stApp [data-testid="stBaseButton-secondary"]:hover,.stApp button[kind="secondary"]:hover,.stApp [data-testid="stDownloadButton"] button:hover,.stApp a[data-testid="stBaseLinkButton-secondary"]:hover,.stApp [data-testid="stLinkButton"] a:hover{border-color:var(--ss-teal)!important;background:#1D2E47!important;color:var(--ss-text)!important}
.stApp [data-testid="stBaseButton-primary"],.stApp button[kind="primary"]{background:var(--ss-teal)!important;color:var(--ss-teal-ink)!important;border:1px solid var(--ss-teal)!important;border-radius:12px!important;font-weight:700!important;min-height:3rem;padding:.65rem 1.9rem!important;box-shadow:0 8px 22px rgba(45,212,191,.22);transition:background .15s,box-shadow .15s}
.stApp [data-testid="stBaseButton-primary"]:hover,.stApp button[kind="primary"]:hover{background:var(--ss-teal-hi)!important;border-color:var(--ss-teal-hi)!important;color:var(--ss-teal-ink)!important;box-shadow:0 10px 26px rgba(45,212,191,.32)}
.stApp [data-testid^="stBase"] p,.stApp [data-testid="stDownloadButton"] p,.stApp [data-testid="stLinkButton"] p{color:inherit!important;margin:0;font-weight:inherit;font-size:.95rem}
.stApp [data-testid="stBaseButton-secondary"]:focus-visible,.stApp [data-testid="stBaseButton-primary"]:focus-visible,.stApp button:focus-visible,.stApp a[data-testid^="stBaseLinkButton"]:focus-visible{outline:2px solid var(--ss-teal)!important;outline-offset:2px!important}
 
.st-key-ex_scam button,.st-key-ex_susp button,.st-key-ex_safe button{min-height:2.35rem!important;padding:.3rem .95rem!important;border-radius:999px!important}
.st-key-ex_scam button p,.st-key-ex_susp button p,.st-key-ex_safe button p{font-size:.88rem!important}
.st-key-ex_scam button::before,.st-key-ex_susp button::before,.st-key-ex_safe button::before{content:"";width:9px;height:9px;border-radius:50%;flex:none}
.st-key-ex_scam button::before{background:var(--ss-red)}
.st-key-ex_susp button::before{background:var(--ss-amber)}
.st-key-ex_safe button::before{background:var(--ss-green)}
[data-testid="stSpinner"]{color:var(--ss-text-2)}
 
@media (max-width:640px){
  .ss-hero{padding-top:16px}
  .ss-card,.st-key-input_card,.st-key-family_card,.st-key-report_card{padding:16px}
  .ss-status{padding:18px}
  .ss-status-title{font-size:1.25rem}
  .ss-gauge{margin:4px auto 0}
  [data-testid="stRadio"]{justify-content:flex-start}
  [data-baseweb="tab-list"]{width:100%}
  .stApp [data-testid="stDownloadButton"] button,.stApp [data-testid="stLinkButton"] a,.stApp a[data-testid="stBaseLinkButton-secondary"]{width:100%}
}

/* ---------- Suraksha Saathi light, welcoming product refresh ---------- */
:root{
  --ss-bg:#F7F9FC; --ss-bg-soft:#F1F6FA; --ss-card:#FFFFFF; --ss-elev:#F4F8FC;
  --ss-line:#DCE6EF; --ss-line-2:#B9CCD9;
  --ss-teal:#0F8A83; --ss-teal-hi:#0B766F; --ss-teal-ink:#FFFFFF;
  --ss-text:#102A4C; --ss-text-2:#425A73; --ss-muted:#61768A;
  --ss-red:#C93645; --ss-amber:#A86608; --ss-green:#17805D;
}
.stApp{background:linear-gradient(180deg,#F7FAFC 0%,#F9F7F1 52%,#F4F8FC 100%)!important;color:var(--ss-text)!important}
[data-testid="stHeader"]{background:rgba(247,250,252,.92)!important}
[data-testid="stMainBlockContainer"],.stMainBlockContainer,.block-container{max-width:1180px!important;padding:1rem 1.35rem 3rem!important}
.ss-brand-name{color:#12345B!important;font-size:1.34rem!important}
.ss-brand-sub{color:#5C7085!important}
.ss-logo{background:linear-gradient(145deg,#B8F0E4,#63CDBD)!important;box-shadow:0 7px 20px rgba(15,138,131,.16)!important;border:1px solid #8DDDD0}
.ss-hero{margin-top:12px;padding:30px 28px 26px!important;border:1px solid #DDEBEF;border-radius:24px;background:radial-gradient(ellipse at 88% 15%,rgba(185,233,225,.58),transparent 36%),linear-gradient(120deg,#FFFFFF 0%,#F4FAF8 58%,#FDF4E9 100%);box-shadow:0 12px 34px rgba(22,54,82,.07);overflow:hidden}
.ss-hero::after{right:18px!important;top:18px!important;width:150px!important;height:180px!important;opacity:.65}
.ss-eyebrow{background:#E6F7F3!important;border-color:#C4E9E2!important;color:#08786F!important}
.ss-hero h1{color:#102A4C!important;max-width:820px!important;font-size:clamp(1.9rem,4vw,3rem)!important}
.ss-hero p{color:#425A73!important;max-width:760px!important}
.ss-trust span{background:rgba(255,255,255,.82)!important;border-color:#DDE8ED!important;color:#294B65!important;border-radius:999px!important;box-shadow:0 2px 7px rgba(16,42,76,.035)}
.ss-card{background:#FFFFFF!important;border-color:#DCE6EF!important;box-shadow:0 7px 22px rgba(24,55,82,.06)!important;color:#102A4C!important}
.ss-card h3,.ss-act h3,.ss-section-title{color:#102A4C!important}
.ss-h-ico{background:#E5F5F2!important;color:#0F827B!important}
.ss-sub{color:#50667D!important}
.ss-muted{color:#65798D!important}
.ss-chip{background:#E6F7F3!important;color:#08786F!important;border-color:#C5E8E2!important}
.ss-chip-muted{background:#F1F5F9!important;color:#50667D!important;border-color:#DCE6EF!important}
.ss-status{box-shadow:0 8px 24px rgba(24,55,82,.07)!important}
.ss-v-SCAM .ss-status-title,.ss-v-SCAM .ss-chip{color:#B42332!important}
.ss-v-CAREFUL .ss-status-title,.ss-v-CAREFUL .ss-chip{color:#8B5608!important}
.ss-v-SAFE .ss-status-title,.ss-v-SAFE .ss-chip{color:#137553!important}
.ss-signs li,.ss-steps li,.ss-details li{background:#F3F7FA!important;color:#263F58!important;border:1px solid #E2EAF0}
.ss-msg{background:#F5F8FB!important;border-color:#DCE6EF!important;color:#1E3854!important}
.ss-msg mark{background:#FFF0B8!important;color:#6F4B00!important;border-bottom-color:#D6A32D!important}
.ss-phr{background:#FFF6D9!important;border-color:#F0D78E!important;color:#765000!important}
.ss-note-info{background:#EAF7F6!important;border-color:#C6E8E4!important;color:#205B59!important}
.ss-note-warn{background:#FFF6DF!important;border-color:#F0D89D!important;color:#765000!important}
.ss-how-item{background:#FFFFFF!important;border-color:#DCE6EF!important;box-shadow:0 5px 18px rgba(24,55,82,.04)}
.ss-how-n{background:#E6F7F3!important;border-color:#C5E8E2!important;color:#08786F!important}
.ss-how-t,.ss-learn-t{color:#173A5C!important}
.ss-how-d{color:#526A80!important}
.ss-learn-n{background:#EAF4FC!important;border-color:#D4E7F4!important;color:#176C9B!important}
.ss-help{background:#EAF8F4!important;border-color:#C8E9DF!important}
.ss-help strong,.ss-steps strong,.ss-callout strong{color:#08786F!important}
.ss-callout{background:#EAF8F4!important;border-color:#C8E9DF!important;color:#244B5A!important}
.ss-big{color:#102A4C!important}
.ss-bar{background:#E1EAF1!important}
.ss-details summary{color:#50667D!important}
.ss-details summary:hover{color:#08786F!important}
.ss-details li b{color:#102A4C!important}
.ss-foot{border-top-color:#DCE6EF!important;color:#64798D!important}
[data-testid="stRadio"] [role="radiogroup"]{background:#FFFFFF!important;border-color:#DCE6EF!important;box-shadow:0 3px 12px rgba(16,42,76,.04)}
[data-testid="stRadio"] label[data-baseweb="radio"]{color:#50667D!important}
[data-testid="stRadio"] label[data-baseweb="radio"]:hover{background:#F0F7F7!important;color:#102A4C!important}
[data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked){background:#0F817A!important;color:#FFFFFF!important}
[data-baseweb="tab-list"]{background:#FFFFFF!important;border-color:#DCE6EF!important;box-shadow:0 4px 14px rgba(16,42,76,.04)}
button[data-baseweb="tab"]{color:#50667D!important}
button[data-baseweb="tab"]:hover{color:#102A4C!important;background:#F1F7F8!important}
button[data-baseweb="tab"][aria-selected="true"]{background:#E4F5F1!important;color:#08786F!important;box-shadow:inset 0 0 0 1px #C7E9E2!important}
.st-key-input_card,.st-key-family_card,.st-key-report_card{background:#FFFFFF!important;border-color:#DCE6EF!important;box-shadow:0 8px 26px rgba(24,55,82,.07)!important}
[data-testid="stTextArea"] [data-baseweb="textarea"],[data-testid="stTextArea"] [data-baseweb="base-input"]{background:#FBFDFF!important;border-color:#C9D9E5!important}
[data-testid="stTextArea"] [data-baseweb="textarea"]:focus-within,[data-testid="stTextArea"] [data-baseweb="base-input"]:focus-within{border-color:#0F8A83!important;box-shadow:0 0 0 3px rgba(15,138,131,.15)!important}
[data-testid="stTextArea"] textarea{color:#173A5C!important;caret-color:#0F8A83!important}
[data-testid="stTextArea"] textarea::placeholder{color:#8092A4!important}
.stApp [data-testid="stBaseButton-secondary"],.stApp button[kind="secondary"],.stApp [data-testid="stDownloadButton"] button,.stApp a[data-testid="stBaseLinkButton-secondary"],.stApp [data-testid="stLinkButton"] a{background:#FFFFFF!important;color:#1D4564!important;border-color:#C9D9E5!important;box-shadow:0 3px 10px rgba(16,42,76,.04)!important}
.stApp [data-testid="stBaseButton-secondary"]:hover,.stApp button[kind="secondary"]:hover,.stApp [data-testid="stDownloadButton"] button:hover,.stApp a[data-testid="stBaseLinkButton-secondary"]:hover,.stApp [data-testid="stLinkButton"] a:hover{border-color:#0F8A83!important;background:#EDF8F6!important;color:#0B5F5A!important}
.stApp [data-testid="stBaseButton-primary"],.stApp button[kind="primary"]{background:linear-gradient(135deg,#116F7D,#0C5B75)!important;color:#FFFFFF!important;border-color:#116F7D!important;box-shadow:0 7px 18px rgba(17,111,125,.20)!important}
.stApp [data-testid="stBaseButton-primary"]:hover,.stApp button[kind="primary"]:hover{background:#0B5F70!important;color:#FFFFFF!important}
.st-key-ex_scam button{background:#FFF0F0!important;color:#A62936!important;border-color:#F3D0D3!important}
.st-key-ex_susp button{background:#FFF6E4!important;color:#80520A!important;border-color:#F1DDAF!important}
.st-key-ex_safe button{background:#EAF8F0!important;color:#176D4C!important;border-color:#C8E9D5!important}
.st-key-ex_scam button::before{background:#D6404F}.st-key-ex_susp button::before{background:#D69A2D}.st-key-ex_safe button::before{background:#259B69}
[data-testid="stSpinner"]{color:#50667D!important}
@media(max-width:640px){.ss-hero{padding:22px 18px!important}.ss-hero h1{font-size:1.85rem!important}.ss-trust{gap:7px}.ss-trust span{font-size:.8rem;padding:7px 10px}}
</style>
"""

HINDI_CSS = """
<style>
.stApp p,.ss,.ss p,.ss li,.ss div,.stApp textarea{line-height:1.75}
.ss-hero h1,.ss-status-title,.ss-section-title,.ss-brand-name{line-height:1.35}
.ss-chip,.ss-eyebrow,.ss-trust span,.ss-label{letter-spacing:0}
</style>
"""
 
_ICONS = {
    "shield": "M12 2.5l8 3v5.5c0 4.8-3.3 9-8 10.5-4.7-1.5-8-5.7-8-10.5V5.5l8-3z",
    "shield-x": "M12 2.5l8 3v5.5c0 4.8-3.3 9-8 10.5-4.7-1.5-8-5.7-8-10.5V5.5l8-3z|M9.5 9.5l5 5|M14.5 9.5l-5 5",
    "shield-check": "M12 2.5l8 3v5.5c0 4.8-3.3 9-8 10.5-4.7-1.5-8-5.7-8-10.5V5.5l8-3z|M8.3 12.2l2.6 2.6 4.9-5.2",
    "alert": "M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z|M12 9v4|M12 17h.01",
    "check": "M22 11.1V12a10 10 0 1 1-5.9-9.1|M22 4L12 14l-3-3",
    "phone": "M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6 19.8 19.8 0 0 1-3.1-8.7A2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1 1 .4 1.9.7 2.8a2 2 0 0 1-.5 2.1L8.1 9.9a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.9.3 1.8.6 2.8.7a2 2 0 0 1 1.7 2z",
    "users": "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2|M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z|M23 21v-2a4 4 0 0 0-3-3.9|M16 3.1a4 4 0 0 1 0 7.8",
    "file": "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z|M14 2v6h6|M16 13H8|M16 17H8|M10 9H8",
    "globe": "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z|M2 12h20|M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z",
    "lock": "M5 11h14v10H5z|M8 11V7a4 4 0 1 1 8 0v4",
    "list": "M9 6h11|M9 12h11|M9 18h11|M4 6h.01|M4 12h.01|M4 18h.01",
    "message": "M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z",
    "info": "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z|M12 16v-4|M12 8h.01",
    "target": "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z|M12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12z|M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z",
}
 
 
def icon(name: str, size: int = 18, stroke: float = 2) -> str:
    d = "".join(f'<path d="{p}"/>' for p in _ICONS[name].split("|"))
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        f'stroke-width="{stroke}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" '
        f'focusable="false">{d}</svg>'
    )
 
 
def logo_svg() -> str:
    return (
        '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#06201E" stroke-width="2.2" '
        'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<path d="M12 2.5l8 3v5.5c0 4.8-3.3 9-8 10.5-4.7-1.5-8-5.7-8-10.5V5.5l8-3z" fill="rgba(6,32,30,.16)"/>'
        '<path d="M8.3 12.2l2.6 2.6 4.9-5.2"/></svg>'
    )
 
 
def md_inline(text: str) -> str:
    """Escape text, then turn **bold** and *italic* into HTML."""
    s = html.escape(str(text))
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"\*(.+?)\*", r"<em>\1</em>", s)
    return s
 
 
def gauge_svg(score: int, color: str, label: str) -> str:
    score = max(0, min(100, int(score)))
    r = 38
    c = 2 * 3.14159265 * r
    arc = ""
    if score > 0:
        arc = (
            f'<circle cx="46" cy="46" r="{r}" fill="none" stroke="{color}" stroke-width="8" '
            f'stroke-linecap="round" stroke-dasharray="{c * score / 100:.1f} {c:.1f}" transform="rotate(-90 46 46)"/>'
        )
    return (
        f'<svg width="108" height="108" viewBox="0 0 92 92" role="img" '
        f'aria-label="{html.escape(label)} {score} / 100">'
        f'<circle cx="46" cy="46" r="{r}" fill="none" stroke="#223049" stroke-width="8"/>{arc}'
        f'<text x="46" y="51" text-anchor="middle" fill="#F1F5F9" font-size="24" font-weight="800">{score}</text>'
        f'<text x="46" y="67" text-anchor="middle" fill="#8EA0B9" font-size="10" font-weight="600">/ 100</text></svg>'
    )
 
 
def notice(kind: str, text: str) -> str:
    ico = "info" if kind == "info" else "alert"
    return f'<div class="ss ss-note ss-note-{kind}">{icon(ico, 18)}<span>{md_inline(text)}</span></div>'
 
 
def card_container(key: str):
    """A styled card. Falls back to a plain container on older Streamlit versions."""
    try:
        return st.container(key=key)
    except TypeError:
        return st.container()
 
 
def highlight_text(text: str, phrases: list) -> str:
    """Escape the text, then wrap suspicious phrases in <mark> in a single pass."""
    safe = html.escape(text)
    uniq = sorted({html.escape(p) for p in phrases if p.strip()}, key=len, reverse=True)
    if uniq:
        parts = []
        for p in uniq:
            esc = re.escape(p)
            parts.append(rf"(?<!\w){esc}(?!\w)" if p.isascii() else esc)
        regex = re.compile("|".join(parts), flags=re.IGNORECASE)
        safe = regex.sub(lambda m: f"<mark>{m.group(0)}</mark>", safe)
    return safe.replace("\n", "<br>")
 
 
# ----------------------------------------------------------------------------
# 5c. PAGE SECTIONS
# ----------------------------------------------------------------------------
def render_topbar(t: dict):
    st.markdown(
        f'<div class="ss ss-topbar"><span class="ss-logo">{logo_svg()}</span>'
        f'<div><div class="ss-brand-name">Suraksha Saathi</div>'
        f'<div class="ss-brand-sub">{html.escape(t["brand_sub"])}</div></div></div>',
        unsafe_allow_html=True,
    )
 
 
def render_hero(t: dict):
    trust_icons = ["globe", "lock", "phone"]
    trust = "".join(f"<span>{icon(i, 16)}{html.escape(x)}</span>" for i, x in zip(trust_icons, t["trust"]))
    st.markdown(
        f'<div class="ss ss-hero"><span class="ss-eyebrow">{icon("shield-check", 15)}{html.escape(t["eyebrow"])}</span>'
        f'<h1>{html.escape(t["hero_h1"])}</h1><p>{html.escape(t["hero_sub"])}</p>'
        f'<div class="ss-trust">{trust}</div></div>',
        unsafe_allow_html=True,
    )
 
 
def render_how(t: dict):
    items = "".join(
        f'<div class="ss-how-item"><span class="ss-how-n">{i}</span><div>'
        f'<div class="ss-how-t">{html.escape(title)}</div><div class="ss-how-d">{html.escape(desc)}</div></div></div>'
        for i, (title, desc) in enumerate(t["how"], 1)
    )
    st.markdown(f'<div class="ss ss-how">{items}</div>', unsafe_allow_html=True)
 
 
def show_result(text: str, lang: str):
    t = T[lang]
    with st.spinner(t["checking"]):
        analysis = get_analysis(text, lang)
    rule_result, llm_result = analysis["rule"], analysis["llm"]
    verdict, score = analysis["verdict"], analysis["score"]
    color = COLORS[verdict]
    chip_label, title = t["status"][verdict]
    one_line = t["verdict"][verdict][1]
    if llm_result and llm_result.get("one_line"):
        one_line = llm_result["one_line"]
    status_icon = {"SCAM": "shield-x", "CAREFUL": "alert", "SAFE": "shield-check"}[verdict]
    ai_chip = t["ai_chip_on"] if llm_result else t["ai_chip_off"]
 
    # 1) Verdict card
    st.markdown(
        f'<div class="ss ss-status ss-v-{verdict}">'
        f'<div class="ss-status-main"><span class="ss-status-ico">{icon(status_icon, 30, 1.8)}</span><div>'
        f'<span class="ss-chip">{html.escape(chip_label)}</span>'
        f'<h2 class="ss-status-title">{html.escape(title)}</h2>'
        f'<p class="ss-status-line">{html.escape(str(one_line))}</p>'
        f'<div class="ss-meta"><span class="ss-chip ss-chip-muted">{html.escape(ai_chip)}</span></div>'
        f'</div></div>'
        f'<div class="ss-gauge">{gauge_svg(score, color, t["gauge"])}'
        f'<span class="ss-gauge-label">{html.escape(t["gauge"])}</span></div></div>',
        unsafe_allow_html=True,
    )
 
    # 2) Why + the message
    reasons = [RULES[c][lang] for c in rule_result["categories"]]
    if llm_result:
        for r in llm_result.get("reasons", []):
            if r not in reasons:
                reasons.append(r)
    if reasons:
        sign_items = "".join(f"<li>{icon('alert', 18)}<span>{html.escape(str(r))}</span></li>" for r in reasons)
    else:
        sign_items = f'<li class="ss-ok">{icon("check", 18)}<span>{html.escape(t["no_signs"])}</span></li>'
    note = notice("info", t["awareness_note"]) if rule_result["awareness"] else ""
 
    phrases = []
    for p in rule_result["keywords"]:
        short = p.strip().lower()
        short = short if len(short) <= 40 else short[:37] + "..."
        if short and short not in phrases:
            phrases.append(short)
    phr_html = ""
    if phrases:
        chips = "".join(f'<span class="ss-phr">{html.escape(p)}</span>' for p in phrases[:12])
        phr_html = f'<div class="ss-label">{html.escape(t["flagged"]).upper()}</div><div class="ss-phrases">{chips}</div>'
 
    st.markdown(
        f'<div class="ss ss-grid ss-v-{verdict}">'
        f'<section class="ss-card"><h3><span class="ss-h-ico">{icon("list", 16)}</span>{html.escape(t["signs_title"])}</h3>'
        f'<ul class="ss-signs">{sign_items}</ul>{note}</section>'
        f'<section class="ss-card"><h3><span class="ss-h-ico">{icon("message", 16)}</span>{html.escape(t["msg_title"])}</h3>'
        f'<div class="ss-msg">{highlight_text(text, rule_result["keywords"])}</div>{phr_html}</section></div>',
        unsafe_allow_html=True,
    )
 
    # 3) What to do now
    if verdict in ("SCAM", "CAREFUL"):
        steps_title, steps = t["steps_title"], t["actions"]
    else:
        steps_title, steps = t["safe_title"], t["safe_tips"]
    step_items = "".join(f"<li><span>{md_inline(s)}</span></li>" for s in steps)
    st.markdown(
        f'<div class="ss ss-card" style="margin-top:16px"><h3><span class="ss-h-ico">{icon("target", 16)}</span>'
        f'{html.escape(steps_title)}</h3><ol class="ss-steps">{step_items}</ol></div>',
        unsafe_allow_html=True,
    )
 
    # 4) Actions: family alert + evidence report
    if verdict in ("SCAM", "CAREFUL"):
        st.markdown('<div style="height:6px"></div>', unsafe_allow_html=True)
        col_a, col_b = st.columns(2)
        with col_a:
            with card_container("family_card"):
                st.markdown(
                    f'<div class="ss ss-act"><h3><span class="ss-h-ico">{icon("users", 16)}</span>{html.escape(t["family"])}</h3>'
                    f'<p class="ss-sub" style="margin-bottom:14px">{html.escape(t["family_desc"])}</p></div>',
                    unsafe_allow_html=True,
                )
                snippet = text.strip().replace("\n", " ")[:200]
                msg = t["family_msg"] + f'"{snippet}"'
                st.link_button(t["family_btn"], "https://wa.me/?text=" + urllib.parse.quote(msg))
        with col_b:
            with card_container("report_card"):
                st.markdown(
                    f'<div class="ss ss-act"><h3><span class="ss-h-ico">{icon("file", 16)}</span>{html.escape(t["report"])}</h3>'
                    f'<p class="ss-sub" style="margin-bottom:14px">{html.escape(t["report_desc"])}</p></div>',
                    unsafe_allow_html=True,
                )
                st.download_button(
                    t["report_btn"],
                    data=build_report(text, analysis).encode("utf-8"),
                    file_name="suraksha_saathi_report.txt",
                    mime="text/plain",
                )
 
 

DRILL_SCENARIOS = {
"en": [
{"title":"Fake CBI officer","steps":[
("Caller: “I am from the CBI. Your Aadhaar is linked to a crime. Stay on video or you will be arrested.”",[
("Hang up and call a trusted person using a number you know",True,"Correct. Real officials do not conduct arrests over video calls. Pause and verify independently."),
("Stay on the call and obey",False,"Fear and pressure are used to control your choices. You can end the call."),
("Send money to prove you are innocent",False,"Never transfer money to a so-called safe or verification account.")]),
("Caller: “This is confidential. Do not tell your family, and keep your camera on.”",[
("Tell family and verify through an official channel",True,"Correct. Secrecy and isolation are major warning signs."),
("Keep it secret because they said it is an investigation",False,"Scammers often stop people from seeking help. Contact someone you trust."),
("Share your OTP to finish verification",False,"Never share OTPs, PINs or passwords with a caller.")]),
("Caller: “Transfer the money in 10 minutes or police will come.”",[
("Do not pay. Hang up and call 1930 for guidance",True,"Correct. Urgent payment threats are a red flag. Call 1930 if you may be targeted."),
("Pay now so the case goes away",False,"Paying does not prove innocence and may lead to more demands."),
("Send bank details so they can check your account",False,"Do not share banking information with the caller.")])]},
{"title":"Fake parcel / SIM-block call","steps":[
("Caller: “Your parcel contains illegal items. Your SIM will be blocked. Press 1 and speak to an officer.”",[
("End the call and verify with the courier or mobile provider using official contact details",True,"Correct. Verify independently; do not rely on numbers or links given by the caller."),
("Give your Aadhaar and address to the caller",False,"Do not hand over personal details to an unverified caller."),
("Move to WhatsApp video because they ask",False,"A video call does not make the caller genuine.")]),
("Caller: “A police case is open. Do not disconnect or tell anyone.”",[
("Hang up and tell someone you trust",True,"Correct. Threats and secrecy are warning signs. You are allowed to end the call."),
("Stay silent and follow every instruction",False,"Pressure is not proof. Stop and verify independently."),
("Send an OTP to cancel the case",False,"An OTP can give someone access to an account. Never share it.")]),
("Caller: “Pay a refundable verification fee now.”",[
("Do not pay. Contact the real provider and call 1930 if needed",True,"Correct. Do not pay a caller to settle an alleged case or unblock a SIM."),
("Pay because they promised a refund",False,"Promises of refunds can be used to trick people into sending money."),
("Continue on the caller's WhatsApp number",False,"Do not continue on a contact channel supplied by the suspicious caller.")])]}],
"hi":[
{"title":"नकली CBI अधिकारी","steps":[
("कॉल करने वाला: “मैं CBI से बोल रहा हूँ। आपका आधार अपराध से जुड़ा है। वीडियो कॉल पर रहें, वरना गिरफ्तार कर लिए जाएंगे।”",[
("कॉल काटें और अपने भरोसेमंद व्यक्ति को खुद कॉल करें",True,"सही। असली अधिकारी वीडियो कॉल पर किसी को गिरफ्तार नहीं करते। रुकें और खुद जांच करें।"),
("कॉल पर रहें और उसकी बात मानें",False,"डराकर ठग आपको काबू में रखना चाहता है। आप कॉल काट सकते हैं।"),
("बेगुनाही साबित करने के लिए पैसे भेजें",False,"किसी ‘सेफ’ या जांच वाले खाते में पैसे न भेजें।")]),
("कॉल करने वाला: “यह गुप्त जांच है। परिवार को मत बताना और कैमरा चालू रखना।”",[
("परिवार को बताएं और आधिकारिक तरीके से जांच करें",True,"सही। चुप रहने और अकेले रहने का दबाव खतरे का संकेत है।"),
("जांच गुप्त है, इसलिए किसी को न बताएं",False,"ठग अक्सर मदद लेने से रोकते हैं। किसी भरोसेमंद व्यक्ति से बात करें।"),
("जांच पूरी करने के लिए OTP बता दें",False,"किसी कॉल करने वाले को OTP, PIN या पासवर्ड न बताएं।")]),
("कॉल करने वाला: “10 मिनट में पैसे भेजो, वरना पुलिस आ जाएगी।”",[
("पैसे न भेजें, कॉल काटें और सलाह के लिए 1930 पर कॉल करें",True,"सही। जल्दी पैसे देने की धमकी खतरे का संकेत है। शक हो तो 1930 पर कॉल करें।"),
("मामला खत्म करने के लिए तुरंत पैसे दें",False,"पैसे देने से बेगुनाही साबित नहीं होती; ठग और पैसे मांग सकता है।"),
("बैंक की जानकारी भेज दें",False,"कॉल करने वाले को बैंक की जानकारी न दें।")])]},
{"title":"नकली पार्सल / SIM बंद होने की कॉल","steps":[
("कॉल करने वाला: “आपके पार्सल में गैर-कानूनी सामान है। आपकी SIM बंद होगी। अधिकारी से बात करने के लिए 1 दबाएं।”",[
("कॉल काटें और कंपनी के आधिकारिक नंबर से खुद जांच करें",True,"सही। कॉल करने वाले के दिए नंबर या लिंक पर भरोसा न करें; खुद आधिकारिक संपर्क ढूंढें।"),
("कॉल करने वाले को आधार और पता बता दें",False,"बिना जांचे कॉल करने वाले को निजी जानकारी न दें।"),
("उसके कहने पर WhatsApp वीडियो कॉल पर जाएं",False,"वीडियो कॉल होने से कोई व्यक्ति असली अधिकारी नहीं बन जाता।")]),
("कॉल करने वाला: “पुलिस केस है। कॉल मत काटना और किसी को मत बताना।”",[
("कॉल काटें और किसी भरोसेमंद व्यक्ति को बताएं",True,"सही। धमकी और चुप रहने का दबाव खतरे के संकेत हैं। आप कॉल काट सकते हैं।"),
("चुप रहें और उसकी हर बात मानें",False,"दबाव डालना सबूत नहीं है। रुकें और खुद जांच करें।"),
("केस रद्द करने के लिए OTP बता दें",False,"OTP से किसी को आपके खाते तक पहुंच मिल सकती है। इसे किसी को न बताएं।")]),
("कॉल करने वाला: “अभी पैसे दो, बाद में वापस मिल जाएंगे।”",[
("पैसे न दें। कंपनी से खुद संपर्क करें; ज़रूरत हो तो 1930 पर कॉल करें",True,"सही। केस खत्म करने या SIM चालू करने के नाम पर कॉल करने वाले को पैसे न दें।"),
("वापस मिलने के वादे पर पैसे दे दें",False,"पैसे लौटाने का वादा भी ठगी का तरीका हो सकता है।"),
("उसका WhatsApp नंबर लेकर बात जारी रखें",False,"संदिग्ध कॉल करने वाले के दिए संपर्क पर बातचीत जारी न रखें।")])]}]}

def show_scam_drill(lang: str, t: dict):
    st.markdown(f'<div class="ss"><h2 class="ss-section-title">{html.escape(t["drill_title"])}</h2><p class="ss-sub">{html.escape(t["drill_intro"])}</p></div>', unsafe_allow_html=True)
    scenario_idx = st.selectbox(t["scenario_label"], [0, 1], format_func=lambda i: t["scenario_options"][i], key="drill_scenario")
    scenario = DRILL_SCENARIOS[lang][scenario_idx]
    state_key = f"drill_state_{lang}_{scenario_idx}"
    state = st.session_state.setdefault(state_key, {"step": 0, "history": [], "answered": False, "feedback": None})
    if state["step"] >= len(scenario["steps"]):
        st.success(t["drill_done"])
        good = sum(state["history"])
        st.metric(t["drill_score"], f'{good} / {len(scenario["steps"])}')
        if good:
            st.success("You made at least one safe choice. Keep pausing and checking before acting." if lang == "en" else "आपने कम-से-कम एक सुरक्षित फैसला लिया। कोई कदम उठाने से पहले रुककर जांचते रहें।")
        st.markdown("**Red flags in this scenario**" if lang == "en" else "**इस अभ्यास में खतरे के संकेत**")
        for caller_line, _ in scenario["steps"]:
            st.markdown("- " + caller_line)
        st.info(t["drill_summary"])
        if st.button(t["restart_drill"], key=f"drill_restart_{lang}_{scenario_idx}"):
            st.session_state[state_key] = {"step": 0, "history": [], "answered": False, "feedback": None}
            st.rerun()
        return
    caller, options = scenario["steps"][state["step"]]
    st.progress(state["step"] / len(scenario["steps"]))
    st.caption(f'{t["step_label"]} {state["step"] + 1} / {len(scenario["steps"])}')
    st.warning(caller)
    st.markdown(f'**{t["choice_label"]}**')
    for oi, (label, is_safe, feedback) in enumerate(options):
        if not state["answered"]:
            if st.button(label, key=f"drill_{lang}_{scenario_idx}_{state['step']}_{oi}", use_container_width=True):
                state["answered"] = True
                state["feedback"] = (is_safe, feedback)
                state["history"].append(1 if is_safe else 0)
                st.rerun()
        else:
            st.button(label, key=f"drill_disabled_{lang}_{scenario_idx}_{state['step']}_{oi}", disabled=True, use_container_width=True)
    if state["answered"]:
        safe, feedback = state["feedback"]
        (st.success if safe else st.error)(feedback)
        if st.button(t["next_step"], key=f"drill_next_{lang}_{scenario_idx}_{state['step']}"):
            state["step"] += 1
            state["answered"] = False
            state["feedback"] = None
            st.rerun()


DRILL_SCENARIOS = {
"en": [
{"title":"Fake CBI officer","steps":[
("Caller: “I am from the CBI. Your Aadhaar is linked to a crime. Stay on video or you will be arrested.”",[
("Hang up and call a trusted person using a number you know",True,"Correct. Real officials do not conduct arrests over video calls. Pause and verify independently."),
("Stay on the call and obey",False,"Fear and pressure are used to control your choices. You can end the call."),
("Send money to prove you are innocent",False,"Never transfer money to a so-called safe or verification account.")]),
("Caller: “This is confidential. Do not tell your family, and keep your camera on.”",[
("Tell family and verify through an official channel",True,"Correct. Secrecy and isolation are major warning signs."),
("Keep it secret because they said it is an investigation",False,"Scammers often stop people from seeking help. Contact someone you trust."),
("Share your OTP to finish verification",False,"Never share OTPs, PINs or passwords with a caller.")]),
("Caller: “Transfer the money in 10 minutes or police will come.”",[
("Do not pay. Hang up and call 1930 for guidance",True,"Correct. Urgent payment threats are a red flag. Call 1930 if you may be targeted."),
("Pay now so the case goes away",False,"Paying does not prove innocence and may lead to more demands."),
("Send bank details so they can check your account",False,"Do not share banking information with the caller.")])]},
{"title":"Fake parcel / SIM-block call","steps":[
("Caller: “Your parcel contains illegal items. Your SIM will be blocked. Press 1 and speak to an officer.”",[
("End the call and verify with the courier or mobile provider using official contact details",True,"Correct. Verify independently; do not rely on numbers or links given by the caller."),
("Give your Aadhaar and address to the caller",False,"Do not hand over personal details to an unverified caller."),
("Move to WhatsApp video because they ask",False,"A video call does not make the caller genuine.")]),
("Caller: “A police case is open. Do not disconnect or tell anyone.”",[
("Hang up and tell someone you trust",True,"Correct. Threats and secrecy are warning signs. You are allowed to end the call."),
("Stay silent and follow every instruction",False,"Pressure is not proof. Stop and verify independently."),
("Send an OTP to cancel the case",False,"An OTP can give someone access to an account. Never share it.")]),
("Caller: “Pay a refundable verification fee now.”",[
("Do not pay. Contact the real provider and call 1930 if needed",True,"Correct. Do not pay a caller to settle an alleged case or unblock a SIM."),
("Pay because they promised a refund",False,"Promises of refunds can be used to trick people into sending money."),
("Continue on the caller's WhatsApp number",False,"Do not continue on a contact channel supplied by the suspicious caller.")])]}],
"hi":[
{"title":"नकली CBI अधिकारी","steps":[
("कॉल करने वाला: “मैं CBI से बोल रहा हूँ। आपका आधार अपराध से जुड़ा है। वीडियो कॉल पर रहें, वरना गिरफ्तार कर लिए जाएंगे।”",[
("कॉल काटें और अपने भरोसेमंद व्यक्ति को खुद कॉल करें",True,"सही। असली अधिकारी वीडियो कॉल पर किसी को गिरफ्तार नहीं करते। रुकें और खुद जांच करें।"),
("कॉल पर रहें और उसकी बात मानें",False,"डराकर ठग आपको काबू में रखना चाहता है। आप कॉल काट सकते हैं।"),
("बेगुनाही साबित करने के लिए पैसे भेजें",False,"किसी ‘सेफ’ या जांच वाले खाते में पैसे न भेजें।")]),
("कॉल करने वाला: “यह गुप्त जांच है। परिवार को मत बताना और कैमरा चालू रखना।”",[
("परिवार को बताएं और आधिकारिक तरीके से जांच करें",True,"सही। चुप रहने और अकेले रहने का दबाव खतरे का संकेत है।"),
("जांच गुप्त है, इसलिए किसी को न बताएं",False,"ठग अक्सर मदद लेने से रोकते हैं। किसी भरोसेमंद व्यक्ति से बात करें।"),
("जांच पूरी करने के लिए OTP बता दें",False,"किसी कॉल करने वाले को OTP, PIN या पासवर्ड न बताएं।")]),
("कॉल करने वाला: “10 मिनट में पैसे भेजो, वरना पुलिस आ जाएगी।”",[
("पैसे न भेजें, कॉल काटें और सलाह के लिए 1930 पर कॉल करें",True,"सही। जल्दी पैसे देने की धमकी खतरे का संकेत है। शक हो तो 1930 पर कॉल करें।"),
("मामला खत्म करने के लिए तुरंत पैसे दें",False,"पैसे देने से बेगुनाही साबित नहीं होती; ठग और पैसे मांग सकता है।"),
("बैंक की जानकारी भेज दें",False,"कॉल करने वाले को बैंक की जानकारी न दें।")])]},
{"title":"नकली पार्सल / SIM बंद होने की कॉल","steps":[
("कॉल करने वाला: “आपके पार्सल में गैर-कानूनी सामान है। आपकी SIM बंद होगी। अधिकारी से बात करने के लिए 1 दबाएं।”",[
("कॉल काटें और कंपनी के आधिकारिक नंबर से खुद जांच करें",True,"सही। कॉल करने वाले के दिए नंबर या लिंक पर भरोसा न करें; खुद आधिकारिक संपर्क ढूंढें।"),
("कॉल करने वाले को आधार और पता बता दें",False,"बिना जांचे कॉल करने वाले को निजी जानकारी न दें।"),
("उसके कहने पर WhatsApp वीडियो कॉल पर जाएं",False,"वीडियो कॉल होने से कोई व्यक्ति असली अधिकारी नहीं बन जाता।")]),
("कॉल करने वाला: “पुलिस केस है। कॉल मत काटना और किसी को मत बताना।”",[
("कॉल काटें और किसी भरोसेमंद व्यक्ति को बताएं",True,"सही। धमकी और चुप रहने का दबाव खतरे के संकेत हैं। आप कॉल काट सकते हैं।"),
("चुप रहें और उसकी हर बात मानें",False,"दबाव डालना सबूत नहीं है। रुकें और खुद जांच करें।"),
("केस रद्द करने के लिए OTP बता दें",False,"OTP से किसी को आपके खाते तक पहुंच मिल सकती है। इसे किसी को न बताएं।")]),
("कॉल करने वाला: “अभी पैसे दो, बाद में वापस मिल जाएंगे।”",[
("पैसे न दें। कंपनी से खुद संपर्क करें; ज़रूरत हो तो 1930 पर कॉल करें",True,"सही। केस खत्म करने या SIM चालू करने के नाम पर कॉल करने वाले को पैसे न दें।"),
("वापस मिलने के वादे पर पैसे दे दें",False,"पैसे लौटाने का वादा भी ठगी का तरीका हो सकता है।"),
("उसका WhatsApp नंबर लेकर बात जारी रखें",False,"संदिग्ध कॉल करने वाले के दिए संपर्क पर बातचीत जारी न रखें।")])]}]}

def show_scam_drill(lang: str, t: dict):
    st.markdown(f'<div class="ss"><h2 class="ss-section-title">{html.escape(t["drill_title"])}</h2><p class="ss-sub">{html.escape(t["drill_intro"])}</p></div>', unsafe_allow_html=True)
    scenario_idx = st.selectbox(t["scenario_label"], [0, 1], format_func=lambda i: t["scenario_options"][i], key="drill_scenario")
    scenario = DRILL_SCENARIOS[lang][scenario_idx]
    state_key = f"drill_state_{lang}_{scenario_idx}"
    state = st.session_state.setdefault(state_key, {"step": 0, "history": [], "answered": False, "feedback": None})
    if state["step"] >= len(scenario["steps"]):
        st.success(t["drill_done"])
        good = sum(state["history"])
        st.metric(t["drill_score"], f'{good} / {len(scenario["steps"])}')
        if good:
            st.success("You made at least one safe choice. Keep pausing and checking before acting." if lang == "en" else "आपने कम-से-कम एक सुरक्षित फैसला लिया। कोई कदम उठाने से पहले रुककर जांचते रहें।")
        st.markdown("**Red flags in this scenario**" if lang == "en" else "**इस अभ्यास में खतरे के संकेत**")
        for caller_line, _ in scenario["steps"]:
            st.markdown("- " + caller_line)
        st.info(t["drill_summary"])
        if st.button(t["restart_drill"], key=f"drill_restart_{lang}_{scenario_idx}"):
            st.session_state[state_key] = {"step": 0, "history": [], "answered": False, "feedback": None}
            st.rerun()
        return
    caller, options = scenario["steps"][state["step"]]
    st.progress(state["step"] / len(scenario["steps"]))
    st.caption(f'{t["step_label"]} {state["step"] + 1} / {len(scenario["steps"])}')
    st.warning(caller)
    st.markdown(f'**{t["choice_label"]}**')
    for oi, (label, is_safe, feedback) in enumerate(options):
        if not state["answered"]:
            if st.button(label, key=f"drill_{lang}_{scenario_idx}_{state['step']}_{oi}", use_container_width=True):
                state["answered"] = True
                state["feedback"] = (is_safe, feedback)
                state["history"].append(1 if is_safe else 0)
                st.rerun()
        else:
            st.button(label, key=f"drill_disabled_{lang}_{scenario_idx}_{state['step']}_{oi}", disabled=True, use_container_width=True)
    if state["answered"]:
        safe, feedback = state["feedback"]
        (st.success if safe else st.error)(feedback)
        if st.button(t["next_step"], key=f"drill_next_{lang}_{scenario_idx}_{state['step']}"):
            state["step"] += 1
            state["answered"] = False
            state["feedback"] = None
            st.rerun()

def show_learn(t: dict):
    cards = ""
    for i, (title, desc) in enumerate(t["learn"], 1):
        clean = re.sub(r"^\d+\.\s*", "", title)
        cards += (
            f'<div class="ss-card ss-learn-card"><span class="ss-learn-n">{i}</span><div>'
            f'<div class="ss-learn-t">{html.escape(clean)}</div><div class="ss-sub">{html.escape(desc)}</div></div></div>'
        )
    help_card = (
        f'<div class="ss-card ss-learn-card ss-help"><span class="ss-learn-n">{icon("phone", 20)}</span><div>'
        f'<div class="ss-learn-t">{html.escape(t["helpline_title"])}</div>'
        f'<div class="ss-sub">{md_inline(t["helpline_body"])}</div></div></div>'
    )
    st.markdown(
        f'<div class="ss"><h2 class="ss-section-title">{html.escape(t["learn_title"])}</h2>'
        f'<p class="ss-sub">{html.escape(t["learn_sub"])}</p><div class="ss-learn">{cards}{help_card}</div>'
        f'<div class="ss-callout">{icon("shield-check", 22)}<div>{md_inline(t["golden"])}</div></div></div>',
        unsafe_allow_html=True,
    )
 
 
FIRST_RUN = {"A": None, "B": "10 / 12", "C": "6 / 12"}
 
 
def show_self_test(lang: str):
    t = T[lang]
    rounds = (("A", t["test_a"], TEST_A), ("B", t["test_b"], TEST_B), ("C", t["test_c"], TEST_C))
    cards = ""
    for key, label, cases in rounds:
        right, total, misses = run_self_test(cases)
        pct = round(100 * right / total) if total else 0
        first = ""
        if FIRST_RUN[key]:
            first = f'<span class="ss-chip ss-chip-muted">{html.escape(t["first_run"])} {FIRST_RUN[key]}</span>'
        if misses:
            rows = "".join(
                f"<li>{html.escape(text[:140])}...<br>{html.escape(t['test_expected'])}: <b>{exp}</b> &nbsp;|&nbsp; "
                f"{html.escape(t['test_got'])}: <b>{got}</b></li>"
                for text, exp, got in misses
            )
            detail = (
                f'<details class="ss-details"><summary>{html.escape(t["test_misses"])} ({len(misses)})</summary>'
                f"<ul>{rows}</ul></details>"
            )
        else:
            detail = f'<p class="ss-muted" style="margin:10px 0 0">{html.escape(t["test_none"])}</p>'
        cards += (
            f'<section class="ss-card"><div class="ss-test-top"><div>'
            f'<div class="ss-test-label">{html.escape(label)}</div>'
            f'<div class="ss-big">{right}<span>/ {total} {html.escape(t["test_correct"])}</span></div></div>'
            f'<span class="ss-chip">{pct}%</span></div>'
            f'<div class="ss-bar" role="img" aria-label="{pct}%"><i style="width:{pct}%"></i></div>'
            f"{first}{detail}</section>"
        )
    st.markdown(
        f'<div class="ss"><h2 class="ss-section-title">{html.escape(t["test_title"])}</h2>'
        f"{notice('info', t['test_note'])}"
        f'<div class="ss-grid" style="margin-top:18px">{cards}</div>'
        f'<p class="ss-muted" style="margin-top:14px">{html.escape(t["test_limit"])}</p></div>',
        unsafe_allow_html=True,
    )
 
 
# ----------------------------------------------------------------------------
# 6. MAIN APP
# ----------------------------------------------------------------------------
st.set_page_config(page_title="Suraksha Saathi", page_icon="🛡️", layout="wide")
 
# Language comes from the selector's saved state (Hindi first, as before)
lang = "hi" if st.session_state.get("lang_choice", "हिन्दी") == "हिन्दी" else "en"
t = T[lang]
 
st.markdown(THEME_CSS + (HINDI_CSS if lang == "hi" else ""), unsafe_allow_html=True)
 
head_left, head_right = st.columns([2, 2])
with head_left:
    render_topbar(t)
with head_right:
    language_col, size_col = st.columns([1, 1])
    with language_col:
        st.radio("Language / भाषा", ["हिन्दी", "English"], horizontal=True, key="lang_choice", label_visibility="collapsed")
    with size_col:
        size_labels = dict(zip(["normal", "large", "xlarge"], t["size_options"]))
        st.selectbox(t["text_size"], ["normal", "large", "xlarge"], format_func=lambda option: size_labels[option], key="text_size_choice", label_visibility="collapsed")
size_choice = st.session_state.get("text_size_choice", "normal")
size_scale = {"normal": 1.0, "large": 1.15, "xlarge": 1.30}.get(size_choice, 1.0)
st.markdown(f"<style>:root{{--ss-text-scale:{size_scale}}} html{{font-size:calc(16px * var(--ss-text-scale, 1))!important}} .stApp p,.stApp label,.stApp li,.stApp button,.stApp textarea,.stApp input,.stApp a,.stApp summary,.stApp h1,.stApp h2,.stApp h3{{font-size:calc(1em * var(--ss-text-scale, 1))!important}} .stButton>button,[data-testid='stDownloadButton'] button{{min-height:44px!important}} button:focus-visible,input:focus-visible,textarea:focus-visible,a:focus-visible{{outline:3px solid #5EEAD4!important;outline-offset:3px!important}} @media(max-width:640px){{[data-testid='stMainBlockContainer'],.block-container{{padding:.8rem .75rem 2rem!important}}}}</style>", unsafe_allow_html=True)
render_hero(t)
 
if "text" not in st.session_state:
    st.session_state.text = ""
if "checked" not in st.session_state:
    st.session_state.checked = None
 
tab_check, tab_learn, tab_test, tab_drill = st.tabs([t["tab_check"], t["tab_learn"], t["tab_test"], t["tab_drill"]])
 
with tab_check:
    with card_container("input_card"):
        st.markdown(
            f'<div class="ss"><h3 style="margin:0 0 4px;padding:0;font-size:1.15rem;font-weight:700;color:#F1F5F9">'
            f'{html.escape(t["card_title"])}</h3><p class="ss-sub" style="margin-bottom:14px">{html.escape(t["card_hint"])}</p></div>',
            unsafe_allow_html=True,
        )
        c1, c2, c3, _spacer = st.columns([1, 1.15, 1, 1.4])
        sample_scam = SAMPLES["SCAM_HI"] if lang == "hi" else SAMPLES["SCAM"]
        if c1.button(t["ex_scam"], key="ex_scam"):
            st.session_state.text = sample_scam
            st.session_state.checked = None
        if c2.button(t["ex_susp"], key="ex_susp"):
            st.session_state.text = SAMPLES["CAREFUL"]
            st.session_state.checked = None
        if c3.button(t["ex_safe"], key="ex_safe"):
            st.session_state.text = SAMPLES["SAFE"]
            st.session_state.checked = None
 
        user_text = st.text_area(
            t["input_label"],
            key="text",
            height=170,
            placeholder=t["placeholder"],
            label_visibility="collapsed",
        )
 
        if st.button(t["button"], type="primary", key="check_btn"):
            if not user_text.strip():
                st.markdown(notice("warn", t["empty"]), unsafe_allow_html=True)
                st.session_state.checked = None
            else:
                st.session_state.checked = user_text.strip()[:3000]
 
    # Keep showing the last result on every rerun (download/WhatsApp clicks must not wipe it)
    if st.session_state.checked:
        show_result(st.session_state.checked, lang)
    else:
        st.markdown(f'<div class="ss ss-label" style="margin-top:22px">{html.escape(t["how_title"]).upper()}</div>', unsafe_allow_html=True)
        render_how(t)
 
    st.markdown(f'<div class="ss"><h3 class="ss-section-title">{html.escape(t["share_title"])}</h3><p class="ss-sub">{html.escape(t["share_note"])}</p></div>', unsafe_allow_html=True)
    if lang == "hi":
        warning_msg = "डिजिटल अरेस्ट स्कैम के 5 संकेत: (1) गिरफ्तारी की धमकी (2) किसी को न बताने का दबाव (3) वीडियो कॉल न काटने को कहना (4) पैसे को ‘सेफ अकाउंट’ में भेजने को कहना (5) तुरंत फैसला करने का दबाव। पुलिस/CBI वीडियो कॉल पर गिरफ्तार नहीं करती और पैसे नहीं मांगती। शक हो तो कॉल काटें और साइबर क्राइम हेल्पलाइन 1930 पर कॉल करें।"
    else:
        warning_msg = "5 signs of a digital arrest scam: (1) Threats of arrest (2) Pressure to keep it secret (3) Demands to stay on a video call (4) Requests to move money to a “safe account” (5) Pressure to act immediately. Police/CBI do not arrest people over video calls or ask for money. If unsure, hang up and call cybercrime helpline 1930."
    st.link_button(t["share_btn"], "https://wa.me/?text=" + urllib.parse.quote(warning_msg), use_container_width=True)
    with st.expander(t["privacy_short"]):
        st.markdown(f'**{t["privacy_title"]}**\n\n{t["privacy_body"]}\n\n**{t["limits_title"]}**\n\n{t["limits_body"]}')

with tab_drill:
    show_scam_drill(lang, t)

with tab_learn:
    show_learn(t)
 
with tab_test:
    show_self_test(lang)
 
st.markdown(f'<div class="ss ss-foot">{html.escape(t["footer"])}</div>', unsafe_allow_html=True)
 
