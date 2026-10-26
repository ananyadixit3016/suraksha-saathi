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
/* Final light-theme overrides for native Streamlit elements */
.stApp,.stApp [data-testid="stMarkdownContainer"],.stApp [data-testid="stMarkdownContainer"] p,.stApp [data-testid="stMarkdownContainer"] li,.stApp [data-testid="stWidgetLabel"],.stApp [data-testid="stWidgetLabel"] p,.stApp [data-testid="stCaptionContainer"],.stApp [data-testid="stTabs"] button{color:#173A5C!important}
.stApp h1,.stApp h2,.stApp h3,.stApp h4,.stApp [data-testid="stMarkdownContainer"] h1,.stApp [data-testid="stMarkdownContainer"] h2,.stApp [data-testid="stMarkdownContainer"] h3{color:#102A4C!important}
.stApp [data-testid="stTextArea"] textarea,.stApp textarea{background:#FBFDFF!important;color:#173A5C!important;-webkit-text-fill-color:#173A5C!important;caret-color:#0F8A83!important}
.stApp [data-testid="stTextArea"] textarea::placeholder,.stApp textarea::placeholder{color:#8092A4!important;-webkit-text-fill-color:#8092A4!important;opacity:1!important}
.stApp [data-testid="stTextArea"] [data-baseweb="textarea"],.stApp [data-testid="stTextArea"] [data-baseweb="base-input"]{background:#FBFDFF!important;border:1px solid #C9D9E5!important}
.stApp [data-testid="stRadio"] label,.stApp [data-testid="stSelectbox"] label{color:#294B65!important}
.stApp [data-baseweb="select"]>div{background:#FFFFFF!important;color:#173A5C!important;border-color:#C9D9E5!important}
.stApp [data-baseweb="select"] span,.stApp [data-baseweb="select"] input{color:#173A5C!important;-webkit-text-fill-color:#173A5C!important}
.stApp [data-baseweb="tab-list"] button{color:#50667D!important}
.stApp [data-baseweb="tab-list"] button[aria-selected="true"]{color:#08786F!important}
/* FINAL VISUAL FIX: reserve Streamlit's top chrome area so it cannot wash out the app */
[data-testid="stHeader"]{display:none!important;height:0!important;}
[data-testid="stToolbar"],[data-testid="stDecoration"]{display:none!important;}
[data-testid="stMainBlockContainer"],.stMainBlockContainer,.block-container{padding-top:0!important;}
.ss-topbar{margin-top:58px!important;min-height:58px;padding:4px 0 10px!important;position:relative;z-index:2;}
/* Keep the language/accessibility controls crisp and aligned, never underneath a translucent header */
.stApp [data-testid="stRadio"] label,.stApp [data-testid="stSelectbox"] label{color:#294B65!important;opacity:1!important;}
.stApp [data-testid="stRadio"] [role="radiogroup"]{background:#EAF2F8!important;border:1px solid #D3E2EC!important;}
.stApp [data-testid="stRadio"] label[data-baseweb="radio"]{color:#244764!important;opacity:1!important;}
.stApp [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked){background:#176EAD!important;color:#FFFFFF!important;}
.stApp [data-baseweb="select"]>div{background:#FFFFFF!important;color:#173A5C!important;border:1px solid #C9D9E5!important;}
.stApp [data-baseweb="select"] span,.stApp [data-baseweb="select"] input{color:#173A5C!important;-webkit-text-fill-color:#173A5C!important;opacity:1!important;}
/* Use the user's chosen warm senior-couple illustration in the hero */
.ss-hero{position:relative;min-height:300px;padding:30px 350px 26px 28px!important;margin-top:16px!important;background:radial-gradient(ellipse at 82% 18%,rgba(185,233,225,.5),transparent 35%),linear-gradient(120deg,#FFFFFF 0%,#F4FAF8 58%,#FDF4E9 100%)!important;}
.ss-hero::after{content:"";position:absolute;right:12px;top:14px;width:330px;height:270px;background-image:url("data:image/jpeg;base64,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")!important;background-repeat:no-repeat!important;background-position:center!important;background-size:contain!important;opacity:1!important;}
.ss-hero h1{color:#102A4C!important;}
.ss-hero p{color:#425A73!important;}
@media(max-width:900px){.ss-hero{padding:24px 22px 210px!important;min-height:0!important;}.ss-hero::after{width:250px;height:190px;right:calc(50% - 125px);top:auto;bottom:8px;}}
@media(max-width:640px){.ss-topbar{margin-top:48px!important;}.ss-hero{padding:22px 18px 180px!important;}.ss-hero::after{width:220px;height:160px;right:calc(50% - 110px);bottom:8px;}}
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
            f'<div class="ss"><h3 style="margin:0 0 4px;padding:0;font-size:1.15rem;font-weight:700;color:#102A4C!important">'
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
 
