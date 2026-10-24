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
            "paise bhejo", "jurmana", "सेफ अकाउंट", "पैसे ट्रांसफर", "पैसे भेजें", "जुर्माना",
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
            r"(update|complete|verify)\s+(your\s+)?kyc\b",
            r"kyc\s+(is\s+)?(expired?|pending|incomplete|update|verification)\b(?!\s+(ho\s+gaya|ho\s+gayi|hogaya|done|completed|ho\s+chuka))",
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

        client = anthropic.Anthropic(api_key=key)
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
        data["score"] = int(data.get("score", 0))
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
COLORS = {"SCAM": "#c62828", "CAREFUL": "#f9a825", "SAFE": "#2e7d32"}


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
        safe = regex.sub(
            lambda m: f"<mark style='background:#ffd54f;padding:0 3px;border-radius:3px'>{m.group(0)}</mark>",
            safe,
        )
    return safe.replace("\n", "<br>")


def combine(rule_result: dict, llm_result):
    """Final verdict = the more cautious of rules and AI. Returns (verdict, score)."""
    if not llm_result:
        return rule_result["verdict"], rule_result["score"]
    verdict = max([rule_result["verdict"], llm_result["verdict"]], key=lambda v: SEVERITY[v])
    score = max(rule_result["score"], llm_result["score"])
    return verdict, score


def get_analysis(text: str, lang: str) -> dict:
    """Analyse once per (text, language) and remember it, so reruns are instant."""
    cache = st.session_state.setdefault("analysis_cache", {})
    key = (text, lang)
    if key not in cache:
        rule_result = rule_analyze(text)
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


def show_result(text: str, lang: str):
    t = T[lang]
    with st.spinner("..."):
        analysis = get_analysis(text, lang)
    rule_result, llm_result = analysis["rule"], analysis["llm"]
    verdict, score = analysis["verdict"], analysis["score"]
    headline, one_line = t["verdict"][verdict]
    if llm_result and llm_result.get("one_line"):
        one_line = llm_result["one_line"]

    text_color = "#222" if verdict == "CAREFUL" else "white"
    st.markdown(
        f"""<div style='background:{COLORS[verdict]};color:{text_color};padding:24px;
        border-radius:14px;text-align:center;margin:12px 0'>
        <div style='font-size:34px;font-weight:800'>{headline}</div>
        <div style='font-size:20px;margin-top:8px'>{html.escape(str(one_line))}</div></div>""",
        unsafe_allow_html=True,
    )
    st.progress(min(max(score, 0), 100) / 100, text=f"{t['score']}: {score}/100")
    st.caption(t["ai_on"] if llm_result else t["ai_off"])

    st.subheader(t["flags"])
    reasons = [RULES[c][lang] for c in rule_result["categories"]]
    if llm_result:
        for r in llm_result.get("reasons", []):
            if r not in reasons:
                reasons.append(r)
    for r in reasons:
        st.markdown(f"- ⚠️ {r}")
    if not reasons:
        st.markdown("- ✅ -")
    if rule_result["awareness"]:
        st.info(t["awareness_note"])

    if rule_result["keywords"]:
        st.caption(t["highlight"])
        st.markdown(
            f"<div style='background:#f5f5f5;color:#222;padding:14px;border-radius:10px;"
            f"font-size:17px;line-height:1.7'>{highlight_text(text, rule_result['keywords'])}</div>",
            unsafe_allow_html=True,
        )

    if verdict in ("SCAM", "CAREFUL"):
        st.subheader(t["do_now"])
        for a in t["actions"]:
            st.markdown(f"✅ {a}")

        st.subheader(t["family"])
        snippet = text.strip().replace("\n", " ")[:200]
        msg = t["family_msg"] + f'"{snippet}"'
        st.link_button(t["family_btn"], "https://wa.me/?text=" + urllib.parse.quote(msg))
        st.caption(t["family_note"])

        st.subheader(t["report"])
        st.download_button(
            t["report_btn"],
            data=build_report(text, analysis).encode("utf-8"),
            file_name="suraksha_saathi_report.txt",
            mime="text/plain",
        )
        st.caption(t["report_note"])


FIRST_RUN = {"A": None, "B": "10 / 12", "C": "6 / 12"}


def show_self_test(lang: str):
    t = T[lang]
    st.header(t["test_title"])
    st.markdown(t["test_note"])
    rounds = (("A", t["test_a"], TEST_A), ("B", t["test_b"], TEST_B), ("C", t["test_c"], TEST_C))
    for key, label, cases in rounds:
        right, total, misses = run_self_test(cases)
        st.metric(label, f"{right} / {total} {t['test_correct']}")
        if FIRST_RUN[key]:
            st.caption(f"{t['first_run']} {FIRST_RUN[key]}")
        if misses:
            st.markdown(f"**{t['test_misses']}**")
            for text, expected, got in misses:
                st.markdown(f"- {html.escape(text[:140])}...  \n  {t['test_expected']}: **{expected}**, {t['test_got']}: **{got}**")
        else:
            st.caption(t["test_none"])
    st.caption(t["test_limit"])


# ----------------------------------------------------------------------------
# 6. MAIN APP
# ----------------------------------------------------------------------------
st.set_page_config(page_title="Suraksha Saathi", page_icon="🛡️", layout="centered")

st.markdown(
    "<style>html, body, [class*='css'] {font-size: 18px;} "
    "textarea {font-size: 18px !important;} "
    "div.stButton > button {font-size: 20px; padding: 0.6rem 1.4rem;}</style>",
    unsafe_allow_html=True,
)

lang_choice = st.radio("Language / भाषा", ["हिन्दी", "English"], horizontal=True)
lang = "hi" if lang_choice == "हिन्दी" else "en"
t = T[lang]

st.title(t["title"])
st.write(t["tagline"])

if "text" not in st.session_state:
    st.session_state.text = ""
if "checked" not in st.session_state:
    st.session_state.checked = None

tab_check, tab_learn, tab_test = st.tabs([t["tab_check"], t["tab_learn"], t["tab_test"]])

with tab_check:
    st.caption(t["samples"])
    c1, c2, c3 = st.columns(3)
    sample_scam = SAMPLES["SCAM_HI"] if lang == "hi" else SAMPLES["SCAM"]
    if c1.button("🔴 Scam" if lang == "en" else "🔴 स्कैम"):
        st.session_state.text = sample_scam
        st.session_state.checked = None
    if c2.button("🟡 Suspicious" if lang == "en" else "🟡 संदिग्ध"):
        st.session_state.text = SAMPLES["CAREFUL"]
        st.session_state.checked = None
    if c3.button("🟢 Normal" if lang == "en" else "🟢 सामान्य"):
        st.session_state.text = SAMPLES["SAFE"]
        st.session_state.checked = None

    user_text = st.text_area(
        t["input_label"],
        key="text",
        height=180,
        placeholder=t["placeholder"],
    )

    if st.button(t["button"], type="primary"):
        if not user_text.strip():
            st.warning(t["empty"])
            st.session_state.checked = None
        else:
            st.session_state.checked = user_text.strip()[:3000]

    # Show the last result on every rerun (so the download/WhatsApp buttons don't wipe it)
    if st.session_state.checked:
        show_result(st.session_state.checked, lang)

with tab_learn:
    st.header(t["learn_title"])
    for title, desc in t["learn"]:
        st.markdown(f"**{title}**  \n{desc}")
    st.info(t["golden"])

with tab_test:
    show_self_test(lang)

st.divider()
st.caption(
    "Prototype built for Hack India AI & Cybersecurity Hackathon. "
    "Not a substitute for official advice. Cybercrime helpline: 1930."
)
