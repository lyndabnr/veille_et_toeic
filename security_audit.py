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
import html
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

# Unique and strict RSS news feeds categorized by domain
FEEDS = {
    "Cybersecurity": {
        "CERT-FR Avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
        "CERT-FR Alertes": "https://www.cert.ssi.gouv.fr/alerte/feed/",
        "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "Krebs on Security": "https://krebsonsecurity.com/feed/",
        "Dark Reading": "https://www.darkreading.com/rss.xml"
    },
    "Artificial Intelligence": {
        "OpenAI News": "https://openai.com/news/rss.xml",
        "TechCrunch AI": "https://techcrunch.com/category/artificial-intelligence/feed/",
        "Actu IA": "https://www.actuia.com/feed/",
        "Hugging Face": "https://huggingface.co/blog/feed.xml",
        "Google Research": "https://research.google/blog/rss/"
    },
    "General IT": {
        "Le Monde Informatique": "https://www.lemondeinformatique.fr/flux-rss/thematique/toutes-les-actualites/rss.xml",
        "ZDNet Actualités": "https://www.zdnet.fr/feeds/rss/actualites/",
        "Wired": "https://www.wired.com/feed/rss",
        "Ars Technica": "https://feeds.arstechnica.com/arstechnica/index"
    },
    "Regulatory Compliance": {
        "ANSSI Actualités": "https://cyber.gouv.fr/actualites/rss/",
        "LINC CNIL (RGPD)": "https://linc.cnil.fr/rss.xml",
        "Global Security Mag (GRC)": "https://www.globalsecuritymag.fr/spip.php?page=backend"
    }
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

def send_telegram_raw_message(token, chat_id, message, parse_mode="Markdown"):
    """Posts a text message to the Telegram bot API."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    
    # POST payload
    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": parse_mode,
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
        
    # Try French date format (typical LINC CNIL: e.g. "Jeudi 9 juillet 2026 - 12:00")
    try:
        months_fr = {
            "janvier": 1, "fevrier": 2, "février": 2, "mars": 3, "avril": 4, "mai": 5, "juin": 6,
            "juillet": 7, "aout": 8, "août": 8, "septembre": 9, "octobre": 10, "novembre": 11, "decembre": 12, "décembre": 12
        }
        m = re.search(r'(?:[a-zA-Zéû\s]+)?(?P<day>\d+)\s+(?P<month>[a-zA-Zéû]+)\s+(?P<year>\d{4})(?:\s*-\s*(?P<hour>\d{2}):(?P<minute>\d{2}))?', date_str.lower())
        if m:
            day = int(m.group("day"))
            month_word = m.group("month")
            month = months_fr.get(month_word, 1)
            year = int(m.group("year"))
            hour = int(m.group("hour")) if m.group("hour") else 12
            minute = int(m.group("minute")) if m.group("minute") else 0
            return datetime(year, month, day, hour, minute, tzinfo=timezone.utc)
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
    desc_pattern = re.compile(r"<description>(.*?)</description>", re.DOTALL | re.IGNORECASE)
    
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
        desc_m = desc_pattern.search(item)
        
        title = clean_cdata(title_m.group(1)) if title_m else "No Title"
        link = clean_cdata(link_m.group(1)) if link_m else ""
        pub_date = clean_cdata(pub_date_m.group(1)) if pub_date_m else ""
        description = clean_cdata(desc_m.group(1)) if desc_m else ""
        
        raw_articles.append((title, link, pub_date, description))
        
    if not raw_articles:
        # Try Atom entry format
        entry_pattern = re.compile(r"<entry>(.*?)</entry>", re.DOTALL | re.IGNORECASE)
        entries = entry_pattern.findall(xml_str)
        updated_pattern = re.compile(r"<(updated|published)>(.*?)</\1>", re.DOTALL | re.IGNORECASE)
        link_atom_pattern = re.compile(r'<link[^>]*href=["\'](.*?)["\']', re.DOTALL | re.IGNORECASE)
        summary_pattern = re.compile(r"<(summary|content)>(.*?)</\1>", re.DOTALL | re.IGNORECASE)
        
        for entry in entries:
            title_m = title_pattern.search(entry)
            link_m = link_atom_pattern.search(entry)
            pub_date_m = updated_pattern.search(entry)
            summary_m = summary_pattern.search(entry)
            
            title = clean_cdata(title_m.group(1)) if title_m else "No Title"
            link = clean_cdata(link_m.group(1)) if link_m else ""
            pub_date = clean_cdata(pub_date_m.group(2)) if pub_date_m else ""
            description = clean_cdata(summary_m.group(2)) if summary_m else ""
            
            raw_articles.append((title, link, pub_date, description))
            
    return raw_articles

def fetch_cyber_news(feed_url):
    """Fetches and parses an RSS feed using urllib, filtering for articles from the last 48 hours and ignoring blacklisted keywords."""
    print(f"[*] Fetching news from: {feed_url}")
    
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
            
            def find_el_text(element, tag_names, attr=None):
                for tname in tag_names:
                    el = element.find(tname)
                    if el is not None:
                        if attr:
                            return el.attrib.get(attr, "").strip()
                        return el.text.strip() if el.text else ""
                return ""
            
            # Detect root namespaces or structure
            if "RDF" in root.tag:
                # RSS 1.0 (RDF)
                ns_item = "{http://purl.org/rss/1.0/}item"
                ns_title = "{http://purl.org/rss/1.0/}title"
                ns_link = "{http://purl.org/rss/1.0/}link"
                ns_date = "{http://purl.org/dc/elements/1.1/}date"
                ns_desc = "{http://purl.org/rss/1.0/}description"
                items = root.findall(ns_item) or root.findall(".//" + ns_item)
                for item in items:
                    title = find_el_text(item, [ns_title, "title"])
                    link = find_el_text(item, [ns_link, "link"])
                    pub_date = find_el_text(item, [ns_date, "pubDate"])
                    description = find_el_text(item, [ns_desc, "description"])
                    raw_articles.append((title, link, pub_date, description))
            else:
                items = root.findall(".//item")
                if items:
                    for item in items:
                        title = find_el_text(item, ["title"])
                        link = find_el_text(item, ["link"])
                        pub_date = find_el_text(item, ["pubDate"])
                        description = find_el_text(item, ["description", "summary", "content"])
                        raw_articles.append((title, link, pub_date, description))
                else:
                    # Atom format
                    entries = root.findall(".//{http://www.w3.org/2005/Atom}entry") or root.findall(".//entry")
                    for entry in entries:
                        title = find_el_text(entry, ["{http://www.w3.org/2005/Atom}title", "title"])
                        link = find_el_text(entry, ["{http://www.w3.org/2005/Atom}link", "link"], attr="href")
                        pub_date = find_el_text(entry, [
                            "{http://www.w3.org/2005/Atom}updated", 
                            "{http://www.w3.org/2005/Atom}published",
                            "updated",
                            "published"
                        ])
                        description = find_el_text(entry, [
                            "{http://www.w3.org/2005/Atom}summary",
                            "{http://www.w3.org/2005/Atom}content",
                            "summary",
                            "content"
                        ])
                        raw_articles.append((title, link, pub_date, description))
        except ET.ParseError as pe:
            # 2. Fall back to regex parser if XML is malformed
            print(f"    [i] XML parsing error ({pe}). Falling back to regex parser...")
            raw_articles = regex_parse_rss(xml_str)
            
        articles = []
        for title, link, pub_date, description in raw_articles:
            # A. Check blacklist exclusion filter
            is_bad, matched_kw = is_blacklisted(title, link)
            if is_bad:
                try:
                    print(f"    [i] Skipped blacklisted article (matched '{matched_kw}'): {title.strip()}")
                except UnicodeEncodeError:
                    try:
                        clean_title = title.strip().encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8')
                        print(f"    [i] Skipped blacklisted article (matched '{matched_kw}'): {clean_title}")
                    except Exception:
                        pass
                continue
                
            # B. Check 48-hour age filter
            dt = parse_feed_date(pub_date)
            if dt and dt >= cutoff_time:
                articles.append({
                    "title": title.strip(),
                    "link": link.strip(),
                    "date": pub_date.strip(),
                    "parsed_date": dt,
                    "description": description.strip() if description else ""
                })
        
        # Sort articles so the most recent ones are first
        articles.sort(key=lambda x: x["parsed_date"], reverse=True)
        return articles
        
    except Exception as e:
        print(f"[-] Error fetching/parsing news from {feed_url}: {e}", file=sys.stderr)
        return []

def escape_html(text):
    """Escapes special HTML characters to prevent breaking Telegram markup."""
    if not text:
        return ""
    return html.escape(text)

def clean_html_description(text):
    """Unescapes HTML entities, strips HTML tags, and cleans white spaces."""
    if not text:
        return ""
    text = html.unescape(text)
    # Strip HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Normalize whitespaces
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def send_digest_to_telegram(digest_categories):
    """Formats and sends a consolidated news digest categorized by domain to Telegram using HTML."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", TELEGRAM_CHAT_ID)

    if not token or not chat_id:
        print("[-] Error: Telegram digest alert requested, but TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not configured.", file=sys.stderr)
        return

    # Check if there are any articles at all
    total_articles = sum(len(articles) for articles in digest_categories.values())
    if total_articles == 0:
        print("[i] No relevant articles published in the last 48 hours for any category. Digest skipped.")
        return

    print(f"[*] Posting consolidated IT, Cyber & AI News Digest to Telegram...")

    category_emojis = {
        "Cybersecurity": "🔒",
        "Artificial Intelligence": "🤖",
        "General IT": "💻",
        "Regulatory Compliance": "📜",
        "Custom Feed": "🔗"
    }

    category_titles_fr = {
        "Cybersecurity": "CYBERSÉCURITÉ",
        "Artificial Intelligence": "INTELLIGENCE ARTIFICIELLE",
        "General IT": "ACTUALITÉS IT & TECH",
        "Regulatory Compliance": "CONFORMITÉ & RÉGLEMENTATION",
        "Custom Feed": "FLUX PERSONNALISÉ"
    }

    for cat_name, articles in digest_categories.items():
        if not articles:
            continue
        
        emoji = category_emojis.get(cat_name, "📢")
        title_fr = category_titles_fr.get(cat_name, cat_name.upper())
        
        # Build category header
        message = f"{emoji} <b>VEILLE {title_fr}</b>\n"
        message += f"🕒 <i>Dernières 48h (sans promotions/bruit)</i>\n\n"
        
        # Display top 10 articles
        for i, art in enumerate(articles[:10], 1):
            title = escape_html(art['title'])
            source = escape_html(art.get('source', ''))
            
            # Format date beautifully
            date_str = ""
            if art.get("date"):
                raw_date = art["date"]
                date_str = raw_date[:16] if len(raw_date) > 16 else raw_date
            
            date_info = f" ({date_str})" if date_str else ""
            
            message += f"{i}. <b>{title}</b>\n"
            message += f"<i>{source}{date_info}</i>\n"
            
            if art.get("description"):
                desc = clean_html_description(art["description"])
                if desc:
                    # Limit description to 150 characters
                    if len(desc) > 150:
                        desc = desc[:147] + "..."
                    message += f"💡 {escape_html(desc)}\n"
            
            message += f"🔗 <a href=\"{art['link']}\">Lire l'article</a>\n\n"
            
        message += "🤖 <i>Envoyé via Security Watch Bot</i>"
        
        # Send message for this category
        send_telegram_raw_message(token, chat_id, message, parse_mode="HTML")

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
        digest_categories = {}
        if args.feed_url:
            # Single custom feed url
            articles = fetch_cyber_news(args.feed_url)
            for art in articles:
                art['source'] = "Custom"
            digest_categories["Custom Feed"] = articles
        else:
            # Categorized feeds
            for category, sources in FEEDS.items():
                category_articles = []
                seen_urls = set()
                
                for source_name, url in sources.items():
                    articles = fetch_cyber_news(url)
                    for art in articles:
                        # Normalize URL to avoid duplicates
                        norm_url = art['link'].split('?')[0].split('#')[0].rstrip('/')
                        if norm_url not in seen_urls:
                            seen_urls.add(norm_url)
                            art['source'] = source_name
                            category_articles.append(art)
                
                # Sort consolidated category articles by date
                category_articles.sort(key=lambda x: x["parsed_date"], reverse=True)
                digest_categories[category] = category_articles
        
        # Send consolidated digest
        send_digest_to_telegram(digest_categories)
    else:
        # Otherwise run log audit
        audit_log(args.log_file, args.threshold, args.json, args.email, args.telegram)
