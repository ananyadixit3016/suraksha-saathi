"""
Suraksha Saathi - Digital Arrest Scam Shield for Senior Citizens
Hybrid system: rule-based scam-pattern engine (always on) + optional LLM analysis.

Run:  streamlit run app.py
"""

import html
import json
import os
import re
import urllib.parse

import streamlit as st

# ----------------------------------------------------------------------------
# 1. SCAM PATTERN RULES (English + Hindi + Hinglish)
# ----------------------------------------------------------------------------
RULES = {
    "arrest_threat": {
        "weight": 30,
        "en": "Threat of arrest or legal action",
        "hi": "गिरफ्तारी या कानूनी कार्रवाई की धमकी",
        "keywords": [
            "arrest", "arrested", "digital arrest", "warrant", "custody", "jail",
            "case registered", "legal action", "girftar", "गिरफ्तार", "गिरफ्तारी",
            "वारंट", "डिजिटल अरेस्ट", "हिरासत", "जेल",
        ],
    },
    "authority": {
        "weight": 15,
        "en": "Claims to be police, CBI, customs or another authority",
        "hi": "पुलिस, CBI, कस्टम या किसी अधिकारी होने का दावा",
        "keywords": [
            "cbi", "police", "mumbai police", "narcotics", "customs", "cyber crime",
            "cybercrime", "supreme court", "enforcement directorate", "trai",
            "पुलिस", "सीबीआई", "कस्टम", "नारकोटिक्स", "साइबर क्राइम", "सुप्रीम कोर्ट",
        ],
    },
    "legal_claim": {
        "weight": 10,
        "en": "Claims your Aadhaar/SIM/parcel is linked to a crime",
        "hi": "आधार/सिम/पार्सल को अपराध से जोड़ने का दावा",
        "keywords": [
            "aadhaar", "aadhar", "sim card", "parcel", "drugs", "money laundering",
            "illegal", "fedex", "आधार", "सिम", "पार्सल", "ड्रग्स", "मनी लॉन्ड्रिंग",
        ],
    },
    "secrecy": {
        "weight": 25,
        "en": "Tells you to keep it secret or not to hang up",
        "hi": "किसी को न बताने या कॉल न काटने का दबाव",
        "keywords": [
            "do not tell", "don't tell", "dont tell", "keep this secret", "confidential",
            "do not disconnect", "don't disconnect", "dont disconnect", "stay on the call",
            "किसी को न बताएं", "किसी को मत बताना", "किसी को न बताना", "कॉल कट मत",
            "कॉल न काटें", "गोपनीय",
        ],
    },
    "money": {
        "weight": 30,
        "en": "Asks you to transfer money / use a 'safe account'",
        "hi": "पैसे ट्रांसफर करने / 'सेफ अकाउंट' में डालने को कहना",
        "keywords": [
            "safe account", "rbi account", "verification fund", "transfer money",
            "transfer the money", "pay fine", "pay the fine", "send money", "upi id",
            "deposit", "सेफ अकाउंट", "पैसे ट्रांसफर", "पैसे भेजें", "जुर्माना",
            "वेरिफिकेशन के लिए पैसे", "आरबीआई अकाउंट",
        ],
    },
    "urgency": {
        "weight": 10,
        "en": "Creates urgency and panic",
        "hi": "जल्दबाज़ी और डर का माहौल बनाना",
        "keywords": [
            "immediately", "within 30 minutes", "within one hour", "urgent", "right now",
            "last warning", "final warning", "तुरंत", "अभी", "आखिरी चेतावनी", "फौरन",
        ],
    },
    "video_call": {
        "weight": 10,
        "en": "Insists on a video call (Skype/WhatsApp) as 'verification'",
        "hi": "वीडियो कॉल (स्काइप/व्हाट्सऐप) पर 'जांच' के नाम पर रोकना",
        "keywords": [
            "video call", "skype", "whatsapp video", "वीडियो कॉल", "स्काइप",
        ],
    },
    "sensitive_info": {
        "weight": 20,
        "en": "Asks for OTP, PIN, CVV or passwords",
        "hi": "OTP, पिन, CVV या पासवर्ड मांगना",
        "keywords": [
            "otp", "pin", "cvv", "password", "aadhaar number", "card number",
            "ओटीपी", "पिन", "पासवर्ड", "कार्ड नंबर",
        ],
    },
}

SEVERITY = {"SAFE": 0, "CAREFUL": 1, "SCAM": 2}


def _pattern(keyword: str) -> str:
    """Word-boundary match for English words; plain match for Hindi."""
    escaped = re.escape(keyword)
    return rf"\b{escaped}\b" if keyword.isascii() else escaped


def rule_analyze(text: str) -> dict:
    """Return matched categories, matched keywords and a 0-100 risk score."""
    lowered = text.lower()
    matched_categories = []
    matched_keywords = []
    score = 0

    for key, rule in RULES.items():
        hits = [k for k in rule["keywords"] if re.search(_pattern(k), lowered)]
        if hits:
            matched_categories.append(key)
            matched_keywords.extend(hits)
            score += rule["weight"]

    # Combination bonus: the classic digital-arrest pattern
    if "arrest_threat" in matched_categories and "money" in matched_categories:
        score += 20
    if "authority" in matched_categories and "secrecy" in matched_categories:
        score += 10

    score = min(score, 100)
    if score >= 60:
        verdict = "SCAM"
    elif score >= 30:
        verdict = "CAREFUL"
    else:
        verdict = "SAFE"

    return {
        "score": score,
        "verdict": verdict,
        "categories": matched_categories,
        "keywords": matched_keywords,
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
# 3. TEXT CONTENT (Hindi + English)
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
        "result": "Result",
        "score": "Risk score",
        "flags": "Why we think so",
        "highlight": "Suspicious phrases highlighted",
        "do_now": "What to do right now",
        "family": "Alert your family",
        "family_btn": "📲 Send alert on WhatsApp",
        "family_note": "Opens WhatsApp with a ready message. You choose who to send it to.",
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
        "learn_title": "5 signs of a digital arrest scam",
        "learn": [
            ("1. Fear of arrest", "They say you or your Aadhaar/SIM/parcel is linked to a crime."),
            ("2. 'Don't tell anyone'", "Scammers isolate you so no one can stop you."),
            ("3. 'Stay on the video call'", "They keep you on camera so you cannot think or call anyone."),
            ("4. 'Move money to a safe account'", "No real agency ever asks for this."),
            ("5. Extreme urgency", "'Within 30 minutes!' is meant to make you panic."),
        ],
        "golden": "**Golden rule:** Police and CBI do not arrest anyone over video call, and they never ask for money. Hang up and call **1930**.",
    },
    "hi": {
        "title": "🛡️ सुरक्षा साथी",
        "tagline": "कोई भी संदिग्ध कॉल या मैसेज चेक करें। कुछ ही सेकंड में सही सलाह पाएं।",
        "input_label": "मैसेज यहाँ पेस्ट करें, या बताएं कि कॉल करने वाले ने क्या कहा:",
        "placeholder": "उदाहरण: मैं CBI से बोल रहा हूँ। आपका आधार अपराध से जुड़ा है। वीडियो कॉल मत काटिए...",
        "button": "अभी जांचें",
        "samples": "उदाहरण आज़माएं:",
        "empty": "कृपया पहले कुछ लिखें या पेस्ट करें।",
        "result": "नतीजा",
        "score": "खतरे का स्कोर",
        "flags": "हमें ऐसा क्यों लगा",
        "highlight": "संदिग्ध शब्द हाइलाइट किए गए",
        "do_now": "अभी क्या करें",
        "family": "परिवार को बताएं",
        "family_btn": "📲 व्हाट्सऐप पर अलर्ट भेजें",
        "family_note": "व्हाट्सऐप में तैयार मैसेज खुलेगा। किसे भेजना है, आप चुनें।",
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
        "learn_title": "डिजिटल अरेस्ट स्कैम की 5 पहचान",
        "learn": [
            ("1. गिरफ्तारी का डर", "वे कहते हैं कि आपका आधार/सिम/पार्सल किसी अपराध से जुड़ा है।"),
            ("2. 'किसी को मत बताना'", "ठग आपको अकेला कर देते हैं ताकि कोई रोक न सके।"),
            ("3. 'वीडियो कॉल पर बने रहिए'", "वे आपको कैमरे पर रखते हैं ताकि आप सोच न सकें।"),
            ("4. 'सेफ अकाउंट में पैसे डालिए'", "कोई असली एजेंसी ऐसा कभी नहीं कहती।"),
            ("5. बहुत जल्दबाज़ी", "'30 मिनट में!' कहकर डराया जाता है।"),
        ],
        "golden": "**सुनहरा नियम:** पुलिस और CBI वीडियो कॉल पर गिरफ्तारी नहीं करती और पैसे नहीं मांगती। कॉल काटें और **1930** पर फोन करें।",
    },
}

SAMPLES = {
    "SCAM": (
        "This is Inspector Sharma from Mumbai Police and CBI. Your Aadhaar is linked to a money "
        "laundering case and a parcel with drugs was found. You are under digital arrest. Do not "
        "disconnect the video call and do not tell anyone. Transfer money to the RBI safe account "
        "immediately for verification or we will issue a warrant."
    ),
    "SCAM_HI": (
        "मैं मुंबई पुलिस से बोल रहा हूँ। आपके आधार से जुड़ा पार्सल पकड़ा गया है जिसमें ड्रग्स हैं। "
        "आप डिजिटल अरेस्ट में हैं। वीडियो कॉल मत काटिए और किसी को मत बताना। "
        "तुरंत सेफ अकाउंट में पैसे ट्रांसफर करें वरना गिरफ्तारी का वारंट निकलेगा।"
    ),
    "CAREFUL": (
        "Your electricity will be cut tonight. Pay the pending bill immediately on this UPI id "
        "to avoid disconnection."
    ),
    "SAFE": "Hi Papa, I will reach home by 7 pm. Please keep dinner ready. Love you.",
}


# ----------------------------------------------------------------------------
# 4. UI HELPERS
# ----------------------------------------------------------------------------
def highlight_text(text: str, keywords: list) -> str:
    """Escape the text, then wrap suspicious phrases in <mark>."""
    safe = html.escape(text)
    for kw in sorted(set(keywords), key=len, reverse=True):
        safe = re.sub(
            _pattern(html.escape(kw)),
            lambda m: f"<mark style='background:#ffd54f;padding:0 3px;border-radius:3px'>{m.group(0)}</mark>",
            safe,
            flags=re.IGNORECASE,
        )
    return safe.replace("\n", "<br>")


def combine(rule_result: dict, llm_result):
    """Final verdict = the more cautious of rules and AI. Returns (verdict, score)."""
    if not llm_result:
        return rule_result["verdict"], rule_result["score"]
    verdict = max(
        [rule_result["verdict"], llm_result["verdict"]], key=lambda v: SEVERITY[v]
    )
    score = max(rule_result["score"], llm_result["score"])
    return verdict, score


COLORS = {"SCAM": "#c62828", "CAREFUL": "#f9a825", "SAFE": "#2e7d32"}


def show_result(text: str, lang: str):
    t = T[lang]
    rule_result = rule_analyze(text)
    with st.spinner("..."):
        llm_result = llm_analyze(text, lang)
    verdict, score = combine(rule_result, llm_result)
    headline, one_line = t["verdict"][verdict]
    if llm_result and llm_result.get("one_line"):
        one_line = llm_result["one_line"]

    st.markdown(
        f"""<div style='background:{COLORS[verdict]};color:white;padding:24px;
        border-radius:14px;text-align:center;margin:12px 0'>
        <div style='font-size:34px;font-weight:800'>{headline}</div>
        <div style='font-size:20px;margin-top:8px'>{one_line}</div></div>""",
        unsafe_allow_html=True,
    )
    st.progress(score / 100, text=f"{t['score']}: {score}/100")
    st.caption(t["ai_on"] if llm_result else t["ai_off"])

    # Reasons
    st.subheader(t["flags"])
    reasons = [RULES[c][lang] for c in rule_result["categories"]]
    if llm_result:
        for r in llm_result.get("reasons", []):
            if r not in reasons:
                reasons.append(r)
    if reasons:
        for r in reasons:
            st.markdown(f"- ⚠️ {r}")
    else:
        st.markdown("- ✅ -")

    # Highlighted text
    if rule_result["keywords"]:
        st.caption(t["highlight"])
        st.markdown(
            f"<div style='background:#f5f5f5;color:#222;padding:14px;border-radius:10px;"
            f"font-size:17px;line-height:1.7'>{highlight_text(text, rule_result['keywords'])}</div>",
            unsafe_allow_html=True,
        )

    # Actions
    if verdict in ("SCAM", "CAREFUL"):
        st.subheader(t["do_now"])
        for a in t["actions"]:
            st.markdown(f"✅ {a}")

        st.subheader(t["family"])
        snippet = text.strip().replace("\n", " ")[:200]
        msg = t["family_msg"] + f'"{snippet}"'
        link = "https://wa.me/?text=" + urllib.parse.quote(msg)
        st.link_button(t["family_btn"], link)
        st.caption(t["family_note"])


# ----------------------------------------------------------------------------
# 5. MAIN APP
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

tab_check, tab_learn = st.tabs([t["tab_check"], t["tab_learn"]])

with tab_check:
    st.caption(t["samples"])
    c1, c2, c3 = st.columns(3)
    sample_scam = SAMPLES["SCAM_HI"] if lang == "hi" else SAMPLES["SCAM"]
    if c1.button("🔴 Scam" if lang == "en" else "🔴 स्कैम"):
        st.session_state.text = sample_scam
    if c2.button("🟡 Suspicious" if lang == "en" else "🟡 संदिग्ध"):
        st.session_state.text = SAMPLES["CAREFUL"]
    if c3.button("🟢 Normal" if lang == "en" else "🟢 सामान्य"):
        st.session_state.text = SAMPLES["SAFE"]

    user_text = st.text_area(
        t["input_label"],
        key="text",
        height=180,
        placeholder=t["placeholder"],
    )

    if st.button(t["button"], type="primary"):
        if not user_text.strip():
            st.warning(t["empty"])
        else:
            show_result(user_text, lang)

with tab_learn:
    st.header(t["learn_title"])
    for title, desc in t["learn"]:
        st.markdown(f"**{title}**  \n{desc}")
    st.info(t["golden"])

st.divider()
st.caption(
    "Prototype built for Hack India AI & Cybersecurity Hackathon. "
    "Not a substitute for official advice. Cybercrime helpline: 1930."
)
