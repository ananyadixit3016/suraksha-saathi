# Suraksha Saathi: Digital Arrest Scam Shield

A calm second opinion for senior citizens and their families about suspicious calls and messages, in simple Hindi or English. Built for the Hack India AI & Cybersecurity Hackathon.

**Live demo:** https://suraksha-saathi-nbxfvmlctlmrghyyxxrjqg.streamlit.app/

## Features
- Paste a message or describe a call for a Green / Yellow / Red verdict and pattern-based risk score.
- Plain-language reasons and highlighted suspicious phrases.
- Clear next steps: hang up, do not pay, call **1930**, and report at cybercrime.gov.in.
- WhatsApp family alert and downloadable evidence summary.
- “Know the 5 signs” education tab and built-in self-test.
- **Scam Drill:** two interactive practice scenarios in English and Hindi, with instant feedback.
- **Text-size control:** Normal / Large / Extra large, remembered during the current session.
- **Share this warning:** a ready-made WhatsApp message with five warning signs and helpline 1930.
- Privacy and limitations notes in both languages.

## How it works
The rule engine (English, Hindi and Hinglish patterns) always runs. An optional Claude layer adds a second opinion if `ANTHROPIC_API_KEY` is configured; the more cautious verdict wins. AI requests have an 8-second timeout, and the app limits attempts to 10 per session per calendar day. If AI is unavailable or fails, the rule-based result is used silently. The public demo may run on rules only.

### Configure Claude (optional)
In Streamlit Community Cloud, open the app's **Settings → Secrets** and add:
```toml
ANTHROPIC_API_KEY = "your-key-here"
```
Do not put the key in `app.py`, commit it to GitHub, or share it in chat. An Anthropic API account and any required billing/credits are separate from a normal Claude chat account. The message text is sent to Anthropic for analysis when AI is enabled.

## Privacy and limitations
This is a prototype, not a trained machine-learning model or official service. Messages may remain in the active app session while you use it, but this prototype does not save them to a database. If AI is enabled, message text is sent to Anthropic. Do not enter passwords, OTPs, or unnecessary personal details. Rule-based scores are not probabilities and can miss rephrased scams or flag genuine messages. If unsure, hang up and call **1930**.

The self-test uses messages written by our own team; it is not an independent benchmark.

## Run locally
```bash
pip install -r requirements.txt
streamlit run app.py
```

## Team
Ananya Dixit, Mohammad Ahad, Shristy Soni
