# Suraksha Saathi: Digital Arrest Scam Shield

A calm second opinion for senior citizens (and their families) about suspicious calls and messages, in simple Hindi or English. Built for the Hack India AI & Cybersecurity Hackathon.

**Live demo:** https://suraksha-saathi-nbxfvmlctlmrghyyxxrjqg.streamlit.app/

## What it does
- Paste a message or describe a call, and get a Green / Yellow / Red verdict with a risk score.
- Explains *why* in plain language and highlights the suspicious phrases.
- Shows what to do now (hang up, do not pay, call **1930**, report at cybercrime.gov.in).
- One-tap WhatsApp alert to a family member.
- Downloadable evidence summary to show the police or attach to a complaint.
- "Know the 5 signs" education tab and a built-in self-test tab.

## How it works
A rule engine (English, Hindi and Hinglish patterns for arrest threats, secrecy, "safe account" demands, urgency, fake authority, OTP requests and more) always runs. An optional Claude layer adds a second opinion when an `ANTHROPIC_API_KEY` is set; the more cautious verdict wins. The public demo runs on rules only.

## Honest limitations
- It is a prototype. No machine-learning model was trained.
- The self-test uses messages written by our own team, so it is not an independent benchmark. On fresh messages written after the rules, the first-run scores were 10/12 and 6/12 before we fixed the rules.
- Rules can miss rephrased scams. If unsure, call 1930.

## Run locally
```
pip install -r requirements.txt
streamlit run app.py
```

## Team
Ananya Dixit, Mohammad Ahad, Shirsty Soni
