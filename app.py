            if c1.button(t["ex_scam"], key="ex_scam", use_container_width=True):
                st.session_state.text = sample_scam
                st.session_state.checked = None
            if c2.button(t["ex_susp"], key="ex_susp", use_container_width=True):
                st.session_state.text = SAMPLES["CAREFUL"]
                st.session_state.checked = None
            if c3.button(t["ex_safe"], key="ex_safe", use_container_width=True):
                st.session_state.text = SAMPLES["SAFE"]
                st.session_state.checked = None

            user_text = st.text_area(
                t["input_label"], key="text", height=112,
                placeholder=t["placeholder"], label_visibility="collapsed",
            )
            action_col, clear_col = st.columns([1, .7])
            with action_col:
                check_clicked = st.button(t["button"], type="primary", key="check_btn", use_container_width=True)
            with clear_col:
                clear_clicked = st.button("Clear" if lang == "en" else "मिटाएँ", key="clear_btn", use_container_width=True)
            if clear_clicked:
                st.session_state.text = ""
                st.session_state.checked = None
                st.rerun()
            if check_clicked:
                if not user_text.strip():
                    st.markdown(notice("warn", t["empty"]), unsafe_allow_html=True)
                    st.session_state.checked = None
                else:
                    st.session_state.checked = user_text.strip()[:3000]

        # Keep the last result visible through reruns, downloads and language changes.
        if st.session_state.checked:
            show_result(st.session_state.checked, lang)

    with tips_col:
        tips_title = "Quick Tips" if lang == "en" else "ज़रूरी सुरक्षा सुझाव"
        tips = (["Never share your OTP, PIN or bank details", "Do not click unknown links", "Do not trust calls claiming to be police, CBI or government officials", "Always verify with official sources"] if lang == "en" else ["OTP, PIN या बैंक की जानकारी कभी साझा न करें", "अनजान लिंक पर क्लिक न करें", "पुलिस, CBI या सरकारी अधिकारी बताने वाली कॉल पर भरोसा न करें", "हमेशा आधिकारिक स्रोतों से पुष्टि करें"])
        quick_html = ''.join(f'<li><span class="ss-tip-check">✓</span><span>{html.escape(item)}</span></li>' for item in tips)
        st.markdown(f'<div class="ss-home-quick"><div class="ss-home-quick-head"><span class="ss-home-quick-icon">✦</span><h3>{tips_title}</h3></div><ul>{quick_html}</ul></div>', unsafe_allow_html=True)
        st.markdown('<div class="ss-side-note"><span class="ss-side-note-icon">🛡</span><div><b>' + ("Remember" if lang == "en" else "याद रखें") + '</b><p>' + ("Real officials will never demand money to prevent an arrest. Pause, hang up, and verify." if lang == "en" else "असली अधिकारी गिरफ्तारी रोकने के लिए पैसे नहीं मांगते। रुकें, कॉल काटें और खुद पुष्टि करें।") + '</p></div></div>', unsafe_allow_html=True)

    # Feature cards and helpline sit immediately beneath the main checker, matching the selected reference layout.
    feature_labels = [
        ("🧠", "Scam Drill" if lang == "en" else "स्कैम अभ्यास", "Test your knowledge with real-life scam scenarios." if lang == "en" else "असली जैसे उदाहरणों से अपनी जानकारी जाँचें।", "#ff5b83", "rgba(255,77,123,.12)"),
        ("🛡", "Safety Tips" if lang == "en" else "सुरक्षा सुझाव", "Simple tips to keep your personal and financial information safe." if lang == "en" else "अपनी निजी और वित्तीय जानकारी सुरक्षित रखें।", "#36b9ff", "rgba(40,145,255,.13)"),
        ("👨‍👩‍👧", "Family Alert" if lang == "en" else "परिवार को सूचित करें", "Share a warning with someone you trust." if lang == "en" else "किसी भरोसेमंद व्यक्ति को चेतावनी भेजें।", "#c26aff", "rgba(165,83,255,.14)"),
        ("♿", "Accessibility" if lang == "en" else "सुलभता", "Use Hindi or English and adjust text size above." if lang == "en" else "हिंदी या English चुनें और ऊपर से अक्षरों का आकार बदलें।", "#38e7c0", "rgba(20,213,172,.12)"),
    ]
    feature_html = ''.join(f'<div class="ss-feature" style="--feature:{color};--feature-bg:{bg}"><div class="ss-feature-icon">{ico}</div><h3>{html.escape(title)}</h3><p>{html.escape(desc)}</p></div>' for ico,title,desc,color,bg in feature_labels)
    st.markdown(f'<div class="ss-feature-grid">{feature_html}</div>', unsafe_allow_html=True)
    helpline_title = "Facing a cybercrime?" if lang == "en" else "क्या आप साइबर अपराध का सामना कर रहे हैं?"
    helpline_sub = "Report it immediately to the national helpline" if lang == "en" else "राष्ट्रीय हेल्पलाइन पर तुरंत रिपोर्ट करें"
    helpline_label = "Cyber Crime Helpline (India)" if lang == "en" else "साइबर क्राइम हेल्पलाइन (भारत)"
    st.markdown(f'<div class="ss-helpline"><div class="ss-helpline-phone">☎</div><div class="ss-helpline-copy"><h3>{helpline_title}</h3><p>{helpline_sub}</p></div><a href="tel:1930" class="ss-helpline-number">☎ &nbsp;1930</a><div class="ss-helpline-label">{helpline_label}</div><div class="ss-helpline-art">✦</div></div>', unsafe_allow_html=True)


    # Supporting guidance follows below the primary actions so users can explore it while scrolling.
    # These sections intentionally span the full page width beneath the checker/tips row.
    st.markdown(f'<div class="ss ss-label" style="margin-top:22px">{html.escape(t["how_title"]).upper()}</div>', unsafe_allow_html=True)
    render_how(t)
    st.markdown(f'<div class="ss" style="margin-top:22px"><h3 class="ss-section-title">{html.escape(t["share_title"])}</h3><p class="ss-sub">{html.escape(t["share_note"])}</p></div>', unsafe_allow_html=True)
    if lang == "hi":
        warning_msg = "डिजिटल अरेस्ट स्कैम के 5 संकेत: (1) गिरफ्तारी की धमकी (2) किसी को न बताने का दबाव (3) वीडियो कॉल न काटने को कहना (4) पैसे को ‘सेफ अकाउंट’ में भेजने को कहना (5) OTP या बैंक की जानकारी मांगना। शक हो तो पैसे न भेजें, कॉल काटें और 1930 पर संपर्क करें।"
    else:
        warning_msg = "5 signs of a digital arrest scam: (1) Threats of arrest (2) Pressure to keep it secret (3) Demands to stay on a video call (4) Requests to move money to a ‘safe account’ (5) Requests for OTPs or banking details. If in doubt, do not pay, hang up, and contact 1930."
    st.link_button(t["share_btn"], "https://wa.me/?text=" + urllib.parse.quote(warning_msg), use_container_width=True)
    with st.expander(t["privacy_short"]):
        st.markdown(f'**{t["privacy_title"]}**\n\n{t["privacy_body"]}\n\n**{t["limits_title"]}**\n\n{t["limits_body"]}')

with tab_link:
    st.markdown("## 🔗 Scam Link Checker" if lang == "en" else "## 🔗 संदिग्ध लिंक की जाँच")
    st.caption("Checks URL patterns only. It does not visit the link or query a live threat-intelligence database." if lang == "en" else "यह केवल URL के पैटर्न जाँचता है। यह लिंक नहीं खोलता और लाइव खतरा डेटाबेस नहीं जाँचता।")
    link_input = st.text_input(
        "Paste a suspicious URL" if lang == "en" else "संदिग्ध URL यहाँ डालें",
        placeholder="https://example.com/login",
        key="standalone_link_input",
    )
    if st.button("Check link" if lang == "en" else "लिंक जाँचें", key="standalone_link_btn", type="primary"):
        result = inspect_url(link_input)
        st.session_state["standalone_link_result"] = result
    result = st.session_state.get("standalone_link_result")
    if result:
        if not result["valid"]:
            st.error("Invalid URL — " + " ".join(result["signals"]))
        else:
            if result["verdict"] == "HIGH":
                st.error(("🚨 High warning level" if lang == "en" else "🚨 उच्च चेतावनी स्तर") + f" · {result['score']}/100")
            elif result["verdict"] == "CAUTION":
                st.warning(("⚠️ Caution — inspect carefully" if lang == "en" else "⚠️ सावधानी से जाँचें") + f" · {result['score']}/100")
            else:
                st.info(("No obvious URL-pattern warning signs" if lang == "en" else "URL में स्पष्ट चेतावनी संकेत नहीं मिले") + f" · {result['score']}/100")
            st.markdown(("**Destination domain:** " if lang == "en" else "**डोमेन:** ") + f"`{result['host']}`")
            st.markdown("**Signals found:**" if lang == "en" else "**मिले संकेत:**")
            for signal in result["signals"]:
                st.markdown(f"- {signal}")
            st.warning("Do not enter passwords, OTPs, or payment details based on this result. A low score does not mean a link is safe." if lang == "en" else "केवल इस परिणाम के आधार पर पासवर्ड, OTP या भुगतान विवरण न डालें। कम स्कोर का अर्थ यह नहीं कि लिंक सुरक्षित है।")

with tab_call:
    st.markdown("## ☎ Suspicious Call Analysis" if lang == "en" else "## ☎ संदिग्ध कॉल का विश्लेषण")
    st.caption("Describe what the caller said. This version analyses a typed description; it does not yet transcribe audio recordings." if lang == "en" else "कॉलर ने क्या कहा, उसका विवरण लिखें। यह संस्करण लिखे गए विवरण का विश्लेषण करता है; अभी ऑडियो रिकॉर्डिंग को टेक्स्ट में नहीं बदलता।")
    call_description = st.text_area(
        "What did the caller say?" if lang == "en" else "कॉलर ने क्या कहा?",
        placeholder=("Example: A caller claimed to be from the police, said my Aadhaar was linked to a crime, and demanded money." if lang == "en" else "उदाहरण: कॉलर ने खुद को पुलिस बताया, आधार को अपराध से जोड़ा और पैसे माँगे।"),
        height=130,
        key="call_description_input",
    )
    if st.button("Analyse call description" if lang == "en" else "कॉल विवरण जाँचें", key="call_description_btn", type="primary"):
        if call_description.strip():
            st.session_state["call_description_checked"] = call_description.strip()[:3000]
        else:
            st.warning("Please describe the call first." if lang == "en" else "पहले कॉल का विवरण लिखें।")
    if st.session_state.get("call_description_checked"):
        show_result(st.session_state["call_description_checked"], lang)

with tab_drill:
    show_scam_drill(lang, t)

with tab_learn:
    show_learn(t)
 
with tab_test:
    show_self_test(lang)
 
st.markdown(f'<div class="ss ss-foot">{html.escape(t["footer"])}</div>', unsafe_allow_html=True)
 
