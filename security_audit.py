#!/usr/bin/env python3
"""
security_audit.py

A simple security audit script that scans a log file to detect potential brute force 
attacks by identifying IP addresses with more than 5 failed login attempts.
It can also export results to JSON, send email alerts, send Telegram alerts,
and fetch latest cyber security news from RSS feeds to post on Telegram.
"""

import os
import re
import sys
import json
import argparse
import smtplib
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
import email.utils
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure Telegram credentials here
TELEGRAM_BOT_TOKEN = "8690266631:AAEoxgo0YLnoxc5h9CwwcvW15wy_vkcILKI"
TELEGRAM_CHAT_ID = "-1004448062967"

DEFAULT_LOG_FILE = "mock_auth.log"
THRESHOLD = 5

# Unique and strict RSS news feeds
FEEDS = {
    "CERT-FR Avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackerNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/"
}

# Blacklist keywords to filter and automatically exclude promotional or off-topic posts
BLACKLIST = ["promo", "deal", "discount", "headphone", "earbuds", "smartphone", "tv", "review", "sale"]

MOCK_LOG_CONTENT = """2026-07-10 21:00:00 - IP: 192.168.1.10 - Status: Failed
2026-07-10 21:00:05 - IP: 192.168.1.10 - Status: Failed
2026-07-10 21:00:10 - IP: 192.168.1.10 - Status: Failed
2026-07-10 21:00:15 - IP: 192.168.1.10 - Status: Failed
2026-07-10 21:00:20 - IP: 192.168.1.10 - Status: Failed
2026-07-10 21:00:25 - IP: 192.168.1.10 - Status: Failed
2026-07-10 21:01:00 - IP: 192.168.1.11 - Status: Failed
2026-07-10 21:01:05 - IP: 192.168.1.11 - Status: Success
2026-07-10 21:02:00 - IP: 10.0.0.5 - Status: Failed
2026-07-10 21:02:10 - IP: 10.0.0.5 - Status: Failed
2026-07-10 21:02:20 - IP: 10.0.0.5 - Status: Failed
2026-07-10 21:02:30 - IP: 10.0.0.5 - Status: Failed
2026-07-10 21:02:40 - IP: 10.0.0.5 - Status: Failed
2026-07-10 21:02:50 - IP: 10.0.0.5 - Status: Failed
2026-07-10 21:03:00 - IP: 172.16.0.4 - Status: Failed
2026-07-10 21:03:10 - IP: 172.16.0.4 - Status: Failed
2026-07-10 21:03:20 - IP: 172.16.0.4 - Status: Success
"""

def generate_mock_log(file_path):
    """Generates a mock auth log file if it does not exist."""
    print(f"[+] Generating mock log file: {file_path}")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(MOCK_LOG_CONTENT)

def export_to_json(output_path, log_file, total_lines, threshold, suspicious_ips):
    """Exports the audit results to a clean JSON file."""
    data = {
        "audit_timestamp": datetime.now().isoformat(),
        "log_file_audited": log_file,
        "total_lines_scanned": total_lines,
        "threshold_limit": threshold,
        "suspicious_ips": suspicious_ips
    }
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Audit results successfully exported to JSON: {output_path}")
    except Exception as e:
        print(f"[-] Error exporting to JSON: {e}", file=sys.stderr)

def send_email_alert(recipient, suspicious_ips, log_file, threshold):
    """Sends an email summary of the detected brute force attempts."""
    smtp_server = os.environ.get("SMTP_SERVER", "localhost")
    smtp_port = int(os.environ.get("SMTP_PORT", "1025"))  # Default to simulation port
    sender_email = os.environ.get("SMTP_SENDER", "security-alerts@local.domain")
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_password = os.environ.get("SMTP_PASSWORD", "")
    use_tls = os.environ.get("SMTP_USE_TLS", "False").lower() in ("true", "1", "yes")

    print(f"[*] Preparing to send email alert to {recipient}...")

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = f"[ALERT] Security Audit: Brute force detected in {log_file}"

    body = f"""Security Audit Report
--------------------------------------
Log File: {log_file}
Threshold: > {threshold} failed login attempts

Potential brute-force attacks detected:
"""
    for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
        body += f"- IP: {ip} ({count} failed attempts)\n"
    
    body += "\nThis is an automated security alert."
    msg.attach(MIMEText(body, 'plain'))

    try:
        if smtp_server == "localhost" and smtp_port == 1025:
            print(f"[i] Simulation Mode: SMTP server is configured to default localhost:1025.")
            print(f"[i] Email Content to send:\n" + "="*45 + f"\nTo: {recipient}\nSubject: {msg['Subject']}\n\n{body}\n" + "="*45)
            
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=5)
        if use_tls:
            server.starttls()
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.sendmail(sender_email, recipient, msg.as_string())
        server.quit()
        print(f"[+] Email alert successfully sent to {recipient}")
    except Exception as e:
        if smtp_server == "localhost" and smtp_port == 1025:
            print("[+] (Simulation success) In a production environment with a configured SMTP server, the email would be delivered.")
        else:
            print(f"[-] Failed to send email via {smtp_server}:{smtp_port} - Error: {e}", file=sys.stderr)

def send_telegram_alert(suspicious_ips, log_file, threshold):
    """Sends a summary of alerts to a Telegram channel/chat using urllib."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", TELEGRAM_CHAT_ID)

    if not token or not chat_id:
        print("[-] Error: Telegram alert requested, but TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not configured.", file=sys.stderr)
        return

    print(f"[*] Preparing to send Telegram alert to Chat ID: {chat_id}...")

    message = f"🚨 *Security Alert: Brute Force Detected*\n\n"
    message += f"📄 *Log File:* `{log_file}`\n"
    message += f"⚠️ *Threshold:* > {threshold} failed attempts\n\n"
    message += f"*Suspicious IPs:*\n"
    for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
        message += f"• `{ip}`: {count} failed attempts\n"
    
    message += "\nThis is an automated security alert."

    send_telegram_raw_message(token, chat_id, message)

def send_telegram_raw_message(token, chat_id, message):
    """Posts a text message to the Telegram bot API."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    
    # POST payload
    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": "true"
    }).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            res_json = json.loads(res_data)
            if res_json.get("ok"):
                print("[+] Telegram message successfully sent.")
            else:
                print(f"[-] Telegram API error: {res_json.get('description')}", file=sys.stderr)
    except Exception as e:
        print(f"[-] Failed to send Telegram message - Error: {e}", file=sys.stderr)

def parse_feed_date(date_str):
    """Parses a date string from an RSS or Atom feed into a timezone-aware datetime object."""
    if not date_str:
        return None
    
    # Try RFC 2822 format (typical RSS pubDate: e.g. "Fri, 10 Jul 2026 14:00:00 GMT")
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
        
    # Try ISO 8601 format (typical Atom updated/published: e.g. "2026-07-10T14:00:00Z")
    try:
        clean_str = date_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
        
    return None

def is_blacklisted(title, link):
    """Checks if an article title or URL contains blacklisted keywords."""
    combined = f"{title} {link}".lower()
    for kw in BLACKLIST:
        if kw in combined:
            return True, kw
    return False, None

def regex_parse_rss(xml_str):
    """Fallback regex parser to extract articles from XML when XML parsing fails."""
    # Find all <item> tags
    item_pattern = re.compile(r"<item>(.*?)</item>", re.DOTALL | re.IGNORECASE)
    items = item_pattern.findall(xml_str)
    raw_articles = []
    
    title_pattern = re.compile(r"<title>(.*?)</title>", re.DOTALL | re.IGNORECASE)
    link_pattern = re.compile(r"<link>(.*?)</link>", re.DOTALL | re.IGNORECASE)
    pub_date_pattern = re.compile(r"<pubDate>(.*?)</pubDate>", re.DOTALL | re.IGNORECASE)
    
    def clean_cdata(text):
        if "<![CDATA[" in text:
            cdata_match = re.search(r"<!\[CDATA\[(.*?)\]\]>", text, re.DOTALL)
            if cdata_match:
                return cdata_match.group(1).strip()
        return text.strip()

    for item in items:
        title_m = title_pattern.search(item)
        link_m = link_pattern.search(item)
        pub_date_m = pub_date_pattern.search(item)
        
        title = clean_cdata(title_m.group(1)) if title_m else "No Title"
        link = clean_cdata(link_m.group(1)) if link_m else ""
        pub_date = clean_cdata(pub_date_m.group(1)) if pub_date_m else ""
        
        raw_articles.append((title, link, pub_date))
        
    if not raw_articles:
        # Try Atom entry format
        entry_pattern = re.compile(r"<entry>(.*?)</entry>", re.DOTALL | re.IGNORECASE)
        entries = entry_pattern.findall(xml_str)
        updated_pattern = re.compile(r"<(updated|published)>(.*?)</\1>", re.DOTALL | re.IGNORECASE)
        link_atom_pattern = re.compile(r'<link[^>]*href=["\'](.*?)["\']', re.DOTALL | re.IGNORECASE)
        
        for entry in entries:
            title_m = title_pattern.search(entry)
            link_m = link_atom_pattern.search(entry)
            pub_date_m = updated_pattern.search(entry)
            
            title = clean_cdata(title_m.group(1)) if title_m else "No Title"
            link = clean_cdata(link_m.group(1)) if link_m else ""
            pub_date = clean_cdata(pub_date_m.group(2)) if pub_date_m else ""
            
            raw_articles.append((title, link, pub_date))
            
    return raw_articles

def fetch_cyber_news(feed_url):
    """Fetches and parses an RSS feed using urllib, filtering for articles from the last 48 hours and ignoring blacklisted keywords."""
    print(f"[*] Fetching cybersecurity news from: {feed_url}")
    
    req = urllib.request.Request(
        feed_url,
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    )
    
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=48)
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            xml_data = response.read()
            
        xml_str = xml_data.decode("utf-8", errors="ignore")
        raw_articles = []
        
        try:
            # 1. Attempt standard XML parsing
            root = ET.fromstring(xml_data)
            items = root.findall(".//item")
            if items:
                for item in items:
                    title = item.find("title").text if item.find("title") is not None else "No Title"
                    link = item.find("link").text if item.find("link") is not None else ""
                    pub_date = item.find("pubDate").text if item.find("pubDate") is not None else ""
                    raw_articles.append((title, link, pub_date))
            else:
                entries = root.findall(".//{http://www.w3.org/2005/Atom}entry") or root.findall(".//entry")
                for entry in entries:
                    title = entry.find("{http://www.w3.org/2005/Atom}title").text if entry.find("{http://www.w3.org/2005/Atom}title") is not None else (entry.find("title").text if entry.find("title") is not None else "No Title")
                    link_el = entry.find("{http://www.w3.org/2005/Atom}link") or entry.find("link")
                    link = ""
                    if link_el is not None:
                        link = link_el.attrib.get("href", link_el.text or "")
                    pub_date_el = entry.find("{http://www.w3.org/2005/Atom}updated") or entry.find("{http://www.w3.org/2005/Atom}published") or entry.find("updated") or entry.find("published")
                    pub_date = pub_date_el.text if pub_date_el is not None else ""
                    raw_articles.append((title, link, pub_date))
        except ET.ParseError as pe:
            # 2. Fall back to regex parser if XML is malformed
            print(f"    [i] XML parsing error ({pe}). Falling back to regex parser...")
            raw_articles = regex_parse_rss(xml_str)
            
        articles = []
        for title, link, pub_date in raw_articles:
            # A. Check blacklist exclusion filter
            is_bad, matched_kw = is_blacklisted(title, link)
            if is_bad:
                print(f"    [i] Skipped blacklisted article (matched '{matched_kw}'): {title.strip()}")
                continue
                
            # B. Check 48-hour age filter
            dt = parse_feed_date(pub_date)
            if dt and dt >= cutoff_time:
                articles.append({
                    "title": title.strip(),
                    "link": link.strip(),
                    "date": pub_date.strip(),
                    "parsed_date": dt
                })
        
        # Sort articles so the most recent ones are first
        articles.sort(key=lambda x: x["parsed_date"], reverse=True)
        return articles[:5]
        
    except Exception as e:
        print(f"[-] Error fetching/parsing news from {feed_url}: {e}", file=sys.stderr)
        return []

def send_news_to_telegram(articles, source_name):
    """Formats and sends a list of cyber news articles to Telegram."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", TELEGRAM_CHAT_ID)

    if not token or not chat_id:
        print("[-] Error: Telegram news alert requested, but TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not configured.", file=sys.stderr)
        return

    if not articles:
        print(f"[i] No relevant articles published in the last 48 hours for source: {source_name}. Skipped.")
        return

    print(f"[*] Posting latest cyber news from {source_name} to Telegram...")

    message = f"📰 *Dernières Actualités Cyber ({source_name})*\n"
    message += f"🕒 _Filtré : Dernières 48 heures (sans bruit / promotions)_\n\n"
    for i, art in enumerate(articles, 1):
        clean_title = art['title'].replace('*', '\\*').replace('_', '\\_').replace('[', '\\[').replace('`', '\\`')
        message += f"{i}. [{clean_title}]({art['link']})\n"
        if art.get("date"):
            date_str = art["date"][:16] if len(art["date"]) > 16 else art["date"]
            message += f"   📅 _{date_str}_\n"
        message += "\n"
        
    message += "🤖 _Envoyé via Security Audit Bot_"
    
    send_telegram_raw_message(token, chat_id, message)

def audit_log(file_path, threshold, json_output=None, email_recipient=None, telegram_alert=False):
    """
    Parses the log file and counts failed login attempts per IP address.
    Flags any IP address exceeding the defined threshold.
    """
    if not os.path.exists(file_path):
        if file_path == DEFAULT_LOG_FILE:
            generate_mock_log(file_path)
        else:
            print(f"[-] Error: Log file '{file_path}' not found.", file=sys.stderr)
            sys.exit(1)

    failed_attempts = defaultdict(int)
    log_pattern = re.compile(r"IP:\s*(?P<ip>[\w\.-]+)\s*-\s*Status:\s*(?P<status>\w+)", re.IGNORECASE)

    total_lines = 0
    parsed_lines = 0

    print(f"[*] Starting audit on log file: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            total_lines += 1
            match = log_pattern.search(line)
            if match:
                parsed_lines += 1
                ip = match.group("ip")
                status = match.group("status").lower()
                if status == "failed":
                    failed_attempts[ip] += 1
            else:
                if "failed" in line.lower() and "ip:" in line.lower():
                    parts = line.split("IP:")
                    if len(parts) > 1:
                        ip_part = parts[1].split("-")[0].strip()
                        failed_attempts[ip_part] += 1
                        parsed_lines += 1

    print(f"[+] Audit completed. Scanned {total_lines} lines (successfully parsed {parsed_lines} entries).")
    print("-" * 60)
    
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}

    if suspicious_ips:
        print(f"[ALERT] Potential brute-force attack detected (threshold: > {threshold} failures):")
        print(f"{'IP Address':<20} | {'Failed Attempts':<15}")
        print("-" * 60)
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:<20} | {count:<15}")
    else:
        print(f"[INFO] No suspicious brute-force activity detected (all IPs <= {threshold} failures).")
    print("-" * 60)

    # Export to JSON if specified
    if json_output:
        export_to_json(json_output, file_path, total_lines, threshold, suspicious_ips)

    # Send email alert if specified and suspicious IPs exist
    if email_recipient:
        if suspicious_ips:
            send_email_alert(email_recipient, suspicious_ips, file_path, threshold)
        else:
            print("[INFO] No suspicious activities to report. Email alert skipped.")

    # Send Telegram alert if requested and suspicious IPs exist
    if telegram_alert:
        if suspicious_ips:
            send_telegram_alert(suspicious_ips, file_path, threshold)
        else:
            print("[INFO] No suspicious activities to report. Telegram alert skipped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a log file to detect potential brute force attacks & pull cyber news.")
    
    # Sub-arguments for audit vs news
    parser.add_argument("log_file", nargs="?", default=DEFAULT_LOG_FILE, help="Path to the log file to scan (default: mock_auth.log)")
    parser.add_argument("-t", "--threshold", type=int, default=THRESHOLD, help="Threshold of failed login attempts to trigger an alert (default: 5)")
    parser.add_argument("-j", "--json", help="Path to a JSON file to write the audit results")
    parser.add_argument("-e", "--email", help="Recipient email address to send alert summary to")
    parser.add_argument("--telegram", action="store_true", help="Send alert summary to Telegram (requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID configuration)")
    
    # News features
    parser.add_argument("--fetch-news", action="store_true", help="Fetch latest cyber news from CERT-FR/The Hacker News/BleepingComputer and send them to Telegram")
    parser.add_argument("--feed-url", help="Override the default RSS feed URL to fetch news from")

    args = parser.parse_args()
    
    # Execute RSS news fetching if requested
    if args.fetch_news:
        if args.feed_url:
            feeds = {"Custom Feed": args.feed_url}
        else:
            feeds = FEEDS
            
        for name, url in feeds.items():
            articles = fetch_cyber_news(url)
            send_news_to_telegram(articles, name)
    else:
        # Otherwise run log audit
        audit_log(args.log_file, args.threshold, args.json, args.email, args.telegram)
