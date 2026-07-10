#!/usr/bin/env python3
"""
english_toeic_bot.py

A Telegram bot that sends daily TOEIC exercises:
- Morning sessions: grammar and vocabulary multiple-choice questions (Part 5 style).
- Evening sessions: short reading comprehension texts with questions and hidden spoiler corrections.
"""

import os
import sys
import json
import random
import argparse
import urllib.request
import urllib.parse

# Telegram configuration
TELEGRAM_BOT_TOKEN = "8679370287:AAEVxXZzJ1zqBTUhaxyAf0_-YdYgke7LdYU"
TELEGRAM_CHAT_ID = "-1003338204025"

# Database of exercises
MORNING_EXERCISES = [
    {
        "id": 1,
        "question": "The marketing director decided to _______ the launch of the new product until the market research was completed.",
        "options": {
            "A": "postpone",
            "B": "cancel",
            "C": "accelerate",
            "D": "promote"
        },
        "answer": "A",
        "explanation": "'Postpone' (reporter) is the correct choice because the launch was delayed 'until the market research was completed'."
    },
    {
        "id": 2,
        "question": "Ms. Jenkins was promoted to regional manager because she handles customer complaints _______ than her peers.",
        "options": {
            "A": "more efficient",
            "B": "most efficiently",
            "C": "more efficiently",
            "D": "efficiency"
        },
        "answer": "C",
        "explanation": "We need the comparative adverb 'more efficiently' to modify the verb 'handles' (handles ... more efficiently than...)."
    },
    {
        "id": 3,
        "question": "Employees are required to obtain written _______ from their department heads before submitting travel reimbursement requests.",
        "options": {
            "A": "approving",
            "B": "approval",
            "C": "approved",
            "D": "approve"
        },
        "answer": "B",
        "explanation": "We need a noun after the adjective 'written'. 'Approval' (approbation) is the noun form."
    },
    {
        "id": 4,
        "question": "Due to _______ weather conditions, the outdoor corporate team-building event has been rescheduled for next week.",
        "options": {
            "A": "adverse",
            "B": "adversity",
            "C": "adversely",
            "D": "opposed"
        },
        "answer": "A",
        "explanation": "We need an adjective to modify the noun 'weather conditions'. 'Adverse' (défavorable/hostile) fits perfectly."
    },
    {
        "id": 5,
        "question": "The board of directors unanimously agreed to _______ the merger proposal during yesterday's meeting.",
        "options": {
            "A": "accept",
            "B": "accepting",
            "C": "acceptance",
            "D": "accepted"
        },
        "answer": "A",
        "explanation": "After 'agreed to', we need the base form of the verb 'accept' to construct the infinitive phrase."
    }
]

EVENING_EXERCISES = [
    {
        "id": 1,
        "text": """<b>Email Message</b>
<b>From:</b> h.davis@globex.com
<b>To:</b> all-staff@globex.com
<b>Date:</b> July 10
<b>Subject:</b> Office Renovation Schedule

Dear Team,
Please be advised that the main lobby renovation will begin this Friday at 6:00 PM. During this period, the front entrance will be closed, and all employees must enter the building through the side door. The construction is expected to be completed by Monday morning. We apologize for any inconvenience.

Best regards,
Helen Davis
Facilities Manager""",
        "question": "What is the main purpose of the email?",
        "options": {
            "A": "To announce a new facilities manager",
            "B": "To inform employees about entry changes due to renovation",
            "C": "To invite staff to an office reopening party",
            "D": "To request volunteers for a construction project"
        },
        "answer": "B",
        "explanation": "The email states that the lobby renovation is starting, the front entrance will be closed, and employees must use the side entrance. Therefore, its purpose is to inform them of entry changes."
    },
    {
        "id": 2,
        "text": """<b>Internal Memo</b>
<b>To:</b> Sales Division
<b>From:</b> Director of Human Resources
<b>Subject:</b> Software Training Session

Starting next month, we will transition to the Apex CRM platform. A mandatory training session is scheduled for Tuesday, August 5, from 9:00 AM to 12:00 PM in Conference Room B. If you cannot attend this session, you must contact HR immediately to schedule a make-up training. Failure to attend will delay your software access.""",
        "question": "What is true about the training session?",
        "options": {
            "A": "It is optional for senior sales managers.",
            "B": "It takes place in Conference Room A.",
            "C": "All sales staff are required to attend it.",
            "D": "It will last for a full day."
        },
        "answer": "C",
        "explanation": "The memo states the training is 'mandatory' (obligatoire) for the Sales Division, which means all sales staff are required to attend it."
    },
    {
        "id": 3,
        "text": """<b>Notice</b>
<b>New Security Badges</b>

Effective September 1, all employees must display their new color-coded photo identification badges at all times while on company premises. Badges can be obtained from the Security Office on the ground floor between 8:00 AM and 4:00 PM. Please bring your old badge and a government-issued photo ID. Replacement of lost badges will incur a fee of $15.""",
        "question": "What must employees do to get a new badge?",
        "options": {
            "A": "Pay a mandatory fee of $15.",
            "B": "Present their old badge and a photo ID.",
            "C": "Email a digital photo to the security head.",
            "D": "Submit a form signed by their supervisor."
        },
        "answer": "B",
        "explanation": "The notice states: 'Please bring your old badge and a government-issued photo ID.' to obtain the new badge."
    }
]

def send_telegram_message(message):
    """Sends a formatted HTML message to the configured Telegram chat."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", TELEGRAM_CHAT_ID)

    if not token or not chat_id:
        print("[-] Error: Telegram bot token or chat ID is not configured.", file=sys.stderr)
        sys.exit(1)

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true"
    }).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            res_json = json.loads(res_data)
            if res_json.get("ok"):
                print("[+] Telegram TOEIC exercise sent successfully.")
            else:
                print(f"[-] Telegram API error: {res_json.get('description')}", file=sys.stderr)
    except Exception as e:
        print(f"[-] Failed to send Telegram message - Error: {e}", file=sys.stderr)

def format_options(options):
    """Formats options dictionary into a clean string using HTML tags."""
    return "\n".join(f"<b>{k}</b>) {v}" for k, v in sorted(options.items()))

def send_morning():
    """Selects and sends a morning grammar/vocab exercise."""
    ex = random.choice(MORNING_EXERCISES)
    
    message = f"☀️ <b>TOEIC Morning Challenge</b> ☀️\n"
    message += f"<i>Part 5 - Incomplete Sentences</i>\n\n"
    message += f"<b>Question:</b>\n{ex['question']}\n\n"
    message += format_options(ex['options']) + "\n\n"
    message += f"💡 <i>Répondez dans votre tête puis cliquez ci-dessous pour révéler la correction :</i>\n\n"
    
    # Correction hidden in Telegram spoiler
    correction = f"✨ <b>Correction :</b> Option <b>{ex['answer']}</b>\n\n"
    correction += f"📖 <b>Explication :</b> {ex['explanation']}"
    
    message += f"<tg-spoiler>{correction}</tg-spoiler>"
    
    print(f"[*] Selecting morning exercise #{ex['id']}...")
    send_telegram_message(message)

def send_evening():
    """Selects and sends an evening reading comprehension exercise."""
    ex = random.choice(EVENING_EXERCISES)
    
    message = f"🌙 <b>TOEIC Evening Session</b> 🌙\n"
    message += f"<i>Part 7 - Reading Comprehension</i>\n\n"
    message += f"📖 <b>Read the text below:</b>\n\n"
    message += f"{ex['text']}\n\n"
    message += f"<b>Question:</b>\n{ex['question']}\n\n"
    message += format_options(ex['options']) + "\n\n"
    message += f"💡 <i>Répondez dans votre tête puis cliquez ci-dessous pour révéler la correction :</i>\n\n"
    
    # Correction hidden in Telegram spoiler
    correction = f"✨ <b>Correction :</b> Option <b>{ex['answer']}</b>\n\n"
    correction += f"📖 <b>Explication :</b> {ex['explanation']}"
    
    message += f"<tg-spoiler>{correction}</tg-spoiler>"
    
    print(f"[*] Selecting evening exercise #{ex['id']}...")
    send_telegram_message(message)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send TOEIC exercises to Telegram.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--morning", action="store_true", help="Send a morning grammar/vocab exercise")
    group.add_argument("--evening", action="store_true", help="Send an evening reading comprehension exercise with explanation")

    args = parser.parse_args()

    if args.morning:
        send_morning()
    elif args.evening:
        send_evening()
