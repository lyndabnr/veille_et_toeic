#!/usr/bin/env python3
"""
cyber_watch.py

Veille cybersecurite vers Telegram, quasi temps reel.

Chaque execution (toutes les ~20 minutes via GitHub Actions) :
  1. interroge les flux RSS/Atom et le catalogue CISA KEV ;
  2. ne garde que ce qui est nouveau (etat persistant, dedoublonnage par URL et titre) ;
  3. envoie tout de suite les ALERTES (alertes CERT-FR, nouvelles entrees CISA KEV,
     signaux critiques : zero-day, exploitation active, vulnerabilite critique...) ;
  4. envoie les autres nouveautes regroupees par categorie ;
  5. signale une source injoignable depuis longtemps.

Aucune dependance externe (bibliotheque standard uniquement).

Usage :
  python cyber_watch.py                      # execution normale (Telegram + etat)
  python cyber_watch.py --dry-run            # affiche les messages, n'envoie rien
  python cyber_watch.py --dry-run --state /tmp/seen.json   # idem, en gardant un etat local
"""

import argparse
import concurrent.futures
import email.utils
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
    PARIS = ZoneInfo("Europe/Paris")
except Exception:  # pragma: no cover
    PARIS = timezone.utc

USER_AGENT = "Mozilla/5.0 (compatible; cyber-watch/2.0; +https://github.com/lyndabnr/veille_et_toeic)"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_FALLBACK_LINK = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

MAX_AGE_DAYS = 3             # ignore les articles plus vieux (evite les reapparitions)
KEV_MAX_AGE_DAYS = 7
SEEN_RETENTION_DAYS = 60     # duree de conservation de l'historique
MAX_ALERTS_PER_RUN = 15      # au-dela, les alertes passent dans le message groupe
MAX_DIGEST_ITEMS_PER_RUN = 40
FAIL_ALERT_AFTER = 36        # echecs consecutifs avant signalement (~12 h a 20 min)
FIRST_RUN_ALERT_WINDOW_H = 24
TELEGRAM_LIMIT = 3800

CAT_NEWS = "Cybersécurité"
CAT_OFFICIAL = "Alertes et avis officiels"
CAT_CTI = "Menaces et CTI"
CAT_OFFENSIVE = "Sécurité offensive et recherche"
CAT_REG = "Réglementation et conformité"
CATEGORY_ORDER = [CAT_OFFICIAL, CAT_NEWS, CAT_CTI, CAT_OFFENSIVE, CAT_REG]

# (nom, url, langue, categorie, niveau) ; niveau "alert" = chaque nouvel element est une alerte
SOURCES = [
    # Alertes et avis officiels
    ("CERT-FR Alertes", "https://cert.cyber.gouv.fr/alerte/feed/", "fr", CAT_OFFICIAL, "alert"),
    ("CERT-FR Avis", "https://cert.cyber.gouv.fr/avis/feed/", "fr", CAT_OFFICIAL, "news"),
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "en", CAT_OFFICIAL, "news"),
    ("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "en", CAT_OFFICIAL, "news"),
    # Actualite cyber
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "en", CAT_NEWS, "news"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "en", CAT_NEWS, "news"),
    ("SecurityWeek", "https://www.securityweek.com/feed/", "en", CAT_NEWS, "news"),
    ("The Record", "https://therecord.media/feed", "en", CAT_NEWS, "news"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/", "en", CAT_NEWS, "news"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml", "en", CAT_NEWS, "news"),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/", "en", CAT_NEWS, "news"),
    ("Schneier on Security", "https://www.schneier.com/feed/atom/", "en", CAT_NEWS, "news"),
    ("ZATAZ", "https://www.zataz.com/feed/", "fr", CAT_NEWS, "news"),
    ("LMI Cybersécurité", "https://www.lemondeinformatique.fr/flux/cybersecurite-conformite.xml", "fr", CAT_NEWS, "news"),
    ("Numerama Cyberguerre", "https://www.numerama.com/cyberguerre/feed/", "fr", CAT_NEWS, "news"),
    ("Global Security Mag", "https://www.globalsecuritymag.fr/spip.php?page=backend", "fr", CAT_NEWS, "news"),
    # Menaces et CTI
    ("CERT-FR CTI", "https://cert.cyber.gouv.fr/cti/feed/", "fr", CAT_CTI, "news"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed.xml", "en", CAT_CTI, "news"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "en", CAT_CTI, "news"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/", "en", CAT_CTI, "news"),
    ("ESET WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/", "en", CAT_CTI, "news"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/", "en", CAT_CTI, "news"),
    ("Sekoia", "https://www.sekoia.com/blog/rss.xml", "en", CAT_CTI, "news"),
    ("Check Point Research", "https://research.checkpoint.com/feed/", "en", CAT_CTI, "news"),
    ("Securelist", "https://securelist.com/feed/", "en", CAT_CTI, "news"),
    ("Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed/index.xml", "en", CAT_CTI, "news"),
    ("Rapid7", "https://www.rapid7.com/rss.xml", "en", CAT_CTI, "news"),
    # Securite offensive et recherche
    ("PortSwigger Research", "https://portswigger.net/research/rss", "en", CAT_OFFENSIVE, "news"),
    ("Google Project Zero", "https://projectzero.google/feed.xml", "en", CAT_OFFENSIVE, "news"),
    # Reglementation et conformite
    ("ANSSI Actualités", "https://cyber.gouv.fr/actualites/rss/", "fr", CAT_REG, "news"),
    ("CERT-FR Actualités", "https://cert.cyber.gouv.fr/actualite/feed/", "fr", CAT_REG, "news"),
    ("CNIL", "https://www.cnil.fr/fr/rss.xml", "fr", CAT_REG, "news"),
    ("LINC CNIL", "https://linc.cnil.fr/rss.xml", "fr", CAT_REG, "news"),
]

# Signaux critiques detectes dans le titre et le resume
STRONG_RE = re.compile(
    r"zero[- ]?day|\b0[- ]?day\b|actively exploited|exploited in the wild|exploitation (is )?(ongoing|active)|"
    r"exploitation active|activement exploit|exploité[es]? (dans la nature|activement)|in the wild|"
    r"emergency (patch|update|fix)|out-of-band|mise à jour d'urgence|correctif d'urgence",
    re.IGNORECASE,
)
# Signaux critiques recherches dans le titre uniquement
TITLE_RE = re.compile(
    r"critical (vulnerabilit|flaw|bug|rce|security)|faille critique|vulnérabilités? critiques?|"
    r"supply[- ]chain attack|attaque (par )?(la )?chaîne d'approvisionnement|cvss (score )?(of )?(9|10)|"
    r"mass[- ]exploitation|exploitation massive",
    re.IGNORECASE,
)
NEGATION_RE = re.compile(
    r"no evidence|not (been )?(actively )?exploited|no (known )?exploitation|aucune? (preuve|exploitation)|pas (été )?exploité",
    re.IGNORECASE,
)
PROMO_RE = re.compile(
    r"\b(promo(tion)?|discount|coupon|giveaway|sponsored|black friday|cyber monday)\b|\bbest vpn\b|\bvpn deals?\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Utilitaires generaux
# ---------------------------------------------------------------------------

def log(msg):
    print(msg, flush=True)


def load_dotenv(path=".env"):
    """Charge un fichier .env local (execution hors GitHub Actions)."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def http_get(url, timeout=20, retries=2, max_bytes=8_000_000):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/rss+xml, application/atom+xml, application/xml, application/json, text/xml, */*",
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(max_bytes)
        except Exception as exc:  # noqa: BLE001
            last = exc
            if attempt + 1 < retries:
                time.sleep(2)
    raise last


def sha(text):
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:16]


def norm_url(url):
    try:
        parts = urllib.parse.urlsplit(url.strip())
        query = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query)
                 if not k.lower().startswith("utm_") and k.lower() not in ("fbclid", "gclid", "ref", "source")]
        return urllib.parse.urlunsplit((parts.scheme.lower(), parts.netloc.lower(),
                                        parts.path.rstrip("/"), urllib.parse.urlencode(query), ""))
    except Exception:  # noqa: BLE001
        return url.strip()


def norm_title(title):
    return re.sub(r"\W+", " ", title.lower()).strip()[:140]


def clean_text(text):
    if not text:
        return ""
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return re.sub(r"\s*The post .{0,300}? appeared first on .*$", "", text).strip()


def truncate(text, limit):
    text = text.strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut.rstrip(" ,;:.") + "..."


def parse_date(value):
    if not value:
        return None
    value = value.strip()
    dt = None
    try:
        dt = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        dt = None
    if dt is None:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_date(dt):
    if dt is None:
        return ""
    return dt.astimezone(PARIS).strftime("%d/%m %H:%M")


# ---------------------------------------------------------------------------
# Lecture des flux
# ---------------------------------------------------------------------------

def _local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _child_text(element, *names):
    for child in element:
        if _local(child.tag) in names:
            text = (child.text or "").strip()
            if text:
                return text
    return ""


def _atom_link(element):
    fallback = ""
    for child in element:
        if _local(child.tag) == "link":
            href = child.attrib.get("href", "")
            if child.attrib.get("rel", "alternate") == "alternate" and href:
                return href
            fallback = fallback or href
    return fallback


def parse_feed(data):
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        text = data.decode("utf-8", "replace")
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
        start = text.find("<")
        root = ET.fromstring(text[start:] if start >= 0 else text)
    entries = []
    for element in root.iter():
        if _local(element.tag) not in ("item", "entry"):
            continue
        title = clean_text(_child_text(element, "title"))
        link = _child_text(element, "link") or _atom_link(element)
        if not link:
            link = _child_text(element, "guid", "id")
        summary = clean_text(_child_text(element, "description", "summary", "encoded", "content"))
        published = parse_date(_child_text(element, "pubDate", "published", "updated", "date"))
        if title and link:
            entries.append({"title": title, "link": link.strip(), "summary": summary, "date": published})
    return entries


def fetch_source(source):
    name, url, lang, category, tier = source
    try:
        entries = parse_feed(http_get(url))
    except Exception as exc:  # noqa: BLE001
        return source, None, str(exc)[:120]
    items = []
    for entry in entries:
        items.append({
            "title": entry["title"], "link": entry["link"], "summary": entry["summary"],
            "date": entry["date"], "source": name, "category": category, "lang": lang,
            "tier": tier, "kind": "rss",
        })
    return source, items, ""


def fetch_kev(now):
    """Nouvelles entrees du catalogue CISA KEV (exploitation active confirmee)."""
    try:
        data = json.loads(http_get(KEV_URL, timeout=30).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)[:120]
    items = []
    limit = now - timedelta(days=KEV_MAX_AGE_DAYS)
    for vuln in data.get("vulnerabilities", []):
        added = parse_date(vuln.get("dateAdded", ""))
        if added is None or added < limit:
            continue
        cve = vuln.get("cveID", "")
        notes = vuln.get("notes", "") or ""
        link = next((part.strip() for part in re.split(r"[ ;]+", notes) if part.startswith("http")), KEV_FALLBACK_LINK)
        ransom = vuln.get("knownRansomwareCampaignUse", "Unknown")
        extra = " Utilisée dans des campagnes de ransomware." if ransom == "Known" else ""
        due = vuln.get("dueDate", "")
        items.append({
            "title": "%s | %s %s : %s" % (cve, vuln.get("vendorProject", ""), vuln.get("product", ""),
                                         vuln.get("vulnerabilityName", "")),
            "link": link,
            "summary": clean_text(vuln.get("shortDescription", "")) + extra
                       + (" Échéance CISA : %s." % due if due else ""),
            "date": added, "source": "CISA KEV", "category": CAT_OFFICIAL, "lang": "en",
            "tier": "alert", "kind": "kev", "uid": "kev:" + cve,
            "reason": "CISA KEV, exploitation active confirmée",
        })
    return items, ""


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify(item):
    """Renvoie (est_alerte, raison)."""
    if item.get("reason"):
        return True, item["reason"]
    if item["tier"] == "alert":
        return True, "Alerte officielle"
    haystack = item["title"] + " " + item["summary"]
    if NEGATION_RE.search(haystack):
        return False, ""
    match = STRONG_RE.search(haystack) or TITLE_RE.search(item["title"])
    if match:
        return True, "Signal critique : " + match.group(0).lower()
    return False, ""


def is_promo(item):
    return item["tier"] != "alert" and bool(PROMO_RE.search(item["title"]))


# ---------------------------------------------------------------------------
# Traduction
# ---------------------------------------------------------------------------

def translate_fr(text):
    if not text:
        return text
    try:
        url = ("https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=fr&dt=t&q="
               + urllib.parse.quote(text[:600]))
        data = json.loads(http_get(url, timeout=10, retries=2).decode("utf-8"))
        out = "".join(chunk[0] for chunk in data[0] if chunk and chunk[0])
        return out or text
    except Exception:  # noqa: BLE001
        return text


def localize(item, with_summary):
    title = item["title"]
    summary = item["summary"]
    if item["lang"] == "en":
        title = translate_fr(title)
        if with_summary and summary:
            summary = translate_fr(truncate(summary, 400))
    return title, summary


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------

def esc(text):
    return html.escape(text, quote=False)


def telegram_send(token, chat_id, text):
    data = urllib.parse.urlencode({
        "chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": "true",
    }).encode()
    for _ in range(3):
        try:
            req = urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % token, data=data)
            with urllib.request.urlopen(req, timeout=20) as resp:
                return bool(json.load(resp).get("ok"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            if exc.code == 429:
                try:
                    wait = int(json.loads(body)["parameters"]["retry_after"])
                except Exception:  # noqa: BLE001
                    wait = 5
                time.sleep(min(wait + 1, 60))
                continue
            log("[-] Telegram HTTP %s : %s" % (exc.code, body[:200]))
            return False
        except Exception as exc:  # noqa: BLE001
            log("[-] Erreur d'envoi Telegram : %s" % type(exc).__name__)
            time.sleep(2)
    return False


class Sender:
    def __init__(self, token, chat_id, dry_run):
        self.token, self.chat_id, self.dry_run = token, chat_id, dry_run
        self.count = 0

    def send(self, text):
        if self.count:
            time.sleep(1.2)  # limite Telegram : ~1 message par seconde par discussion
        self.count += 1
        if self.dry_run:
            print("-" * 60 + "\n" + re.sub(r"<[^>]+>", "", html.unescape(text)))
            return True
        return telegram_send(self.token, self.chat_id, text)


def format_alert(item, reason):
    title, summary = localize(item, with_summary=True)
    lines = ["<b>ALERTE | %s</b>" % esc(reason),
             '<a href="%s">%s</a>' % (html.escape(item["link"], quote=True), esc(title))]
    if summary:
        lines.append(esc(truncate(summary, 280)))
    meta = item["source"] + (" | " + fmt_date(item["date"]) if item["date"] else "")
    lines.append(esc(meta))
    return "\n".join(lines)


def build_digest(items):
    """Regroupe par categorie et decoupe en messages de taille raisonnable."""
    by_cat = {}
    for item in items:
        by_cat.setdefault(item["category"], []).append(item)
    total = len(items)
    header = "<b>Veille cyber | %d nouveauté%s</b>" % (total, "s" if total > 1 else "")
    messages, current, current_items = [], [header], []
    size = len(header)
    for category in CATEGORY_ORDER + [c for c in by_cat if c not in CATEGORY_ORDER]:
        group = by_cat.get(category)
        if not group:
            continue
        group.sort(key=lambda it: it["date"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        block_head = "\n<b>%s</b>" % esc(category)
        if size + len(block_head) > TELEGRAM_LIMIT:
            messages.append(("\n".join(current), current_items))
            current, current_items, size = [header + " (suite)"], [], len(header) + 8
        current.append(block_head)
        size += len(block_head)
        for item in group:
            title, _ = localize(item, with_summary=False)
            line = '• <a href="%s">%s</a> (%s)' % (html.escape(item["link"], quote=True),
                                                  esc(truncate(title, 160)), esc(item["source"]))
            if size + len(line) > TELEGRAM_LIMIT:
                messages.append(("\n".join(current), current_items))
                current = [header + " (suite)", block_head]
                current_items, size = [], len(header) + len(block_head) + 8
            current.append(line)
            current_items.append(item)
            size += len(line) + 1
    if current_items:
        messages.append(("\n".join(current), current_items))
    return messages


# ---------------------------------------------------------------------------
# Etat persistant
# ---------------------------------------------------------------------------

def load_state(path):
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                state = json.load(fh)
            state.setdefault("seen", {})
            state.setdefault("health", {})
            return state, False
        except (OSError, ValueError):
            log("[-] Fichier d'état illisible, il sera recréé (premier lancement simulé).")
    return {"version": 2, "seen": {}, "health": {}}, True


def save_state(path, state, now):
    if not path:
        return
    limit = int((now - timedelta(days=SEEN_RETENTION_DAYS)).timestamp())
    state["seen"] = {k: v for k, v in state["seen"].items() if v >= limit}
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, path)


def keys_for(item):
    uid = item.get("uid") or norm_url(item["link"])
    return [sha("u:" + uid), sha("t:" + norm_title(item["title"]))]


# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Veille cybersécurité vers Telegram.")
    parser.add_argument("--dry-run", action="store_true", help="affiche les messages sans les envoyer")
    parser.add_argument("--state", default=None, help="chemin du fichier d'état (défaut : state/seen.json)")
    args = parser.parse_args()

    load_dotenv()
    token = os.environ.get("TELEGRAM_BOT_TOKEN_WATCH") or os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID_WATCH") or os.environ.get("TELEGRAM_CHAT_ID", "")
    if not args.dry_run and (not token or not chat_id):
        log("[-] TELEGRAM_BOT_TOKEN_WATCH / TELEGRAM_CHAT_ID_WATCH non configurés.")
        return 1

    state_path = args.state if args.state else (None if args.dry_run else "state/seen.json")
    state, first_run = load_state(state_path)
    now = datetime.now(timezone.utc)
    sender = Sender(token, chat_id, args.dry_run)

    # 1. Collecte
    collected, failures = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(fetch_source, SOURCES))
    for source, items, error in results:
        name = source[0]
        health = state["health"].setdefault(name, {"fails": 0, "alerted": False})
        if items is None:
            health["fails"] += 1
            failures.append((name, error))
            log("[-] %s : %s" % (name, error))
        else:
            health["fails"], health["alerted"] = 0, False
            collected.extend(items)
    kev_items, kev_error = fetch_kev(now)
    kev_health = state["health"].setdefault("CISA KEV", {"fails": 0, "alerted": False})
    if kev_items is None:
        kev_health["fails"] += 1
        log("[-] CISA KEV : %s" % kev_error)
    else:
        kev_health["fails"], kev_health["alerted"] = 0, False
        collected.extend(kev_items)
    log("[*] %d éléments récupérés, %d source(s) en échec." % (len(collected), len(failures)))

    # 2. Filtrage : age, doublons, nouveautes
    age_limit = now - timedelta(days=MAX_AGE_DAYS)
    seen = state["seen"]
    fresh, run_keys = [], set()
    for item in collected:
        if item["kind"] == "rss" and item["date"] and item["date"] < age_limit:
            continue
        keys = keys_for(item)
        if any(k in seen for k in keys) or any(k in run_keys for k in keys):
            continue
        run_keys.update(keys)
        item["keys"] = keys
        fresh.append(item)
    log("[*] %d nouveauté(s) détectée(s)." % len(fresh))

    stamp = int(now.timestamp())

    def mark(item):
        for key in item["keys"]:
            seen[key] = stamp

    alerts, digest = [], []
    for item in fresh:
        if is_promo(item):
            mark(item)  # contenu promotionnel : ignoré définitivement
            continue
        flag, reason = classify(item)
        (alerts if flag else digest).append((item, reason) if flag else item)

    # 3. Premier lancement : on amorce l'historique sans inonder le canal
    if first_run:
        window = now - timedelta(hours=FIRST_RUN_ALERT_WINDOW_H)
        recent = [(it, r) for it, r in alerts if (it["date"] or now) >= window][:5]
        for item in [a[0] for a in alerts] + digest:
            mark(item)
        intro = ("<b>Veille cyber activée</b>\n%d sources surveillées, contrôle toutes les 20 minutes environ.\n"
                 "Les alertes (CERT-FR, CISA KEV, zero-day, exploitation active) arrivent immédiatement, "
                 "le reste est regroupé par catégorie." % (len(SOURCES) + 1))
        sender.send(intro)
        for item, reason in sorted(recent, key=lambda p: p[0]["date"] or now):
            sender.send(format_alert(item, reason))
        save_state(state_path, state, now)
        return 0

    # 4. Alertes immediates
    alerts.sort(key=lambda p: p[0]["date"] or now)
    overflow = alerts[MAX_ALERTS_PER_RUN:]
    for item, reason in alerts[:MAX_ALERTS_PER_RUN]:
        if sender.send(format_alert(item, reason)):
            mark(item)
    digest.extend(item for item, _ in overflow)

    # 5. Message groupe
    batch = digest[:MAX_DIGEST_ITEMS_PER_RUN]
    if batch:
        for text, items_in_message in build_digest(batch):
            if sender.send(text):
                for item in items_in_message:
                    mark(item)
    if len(digest) > len(batch):
        log("[*] %d élément(s) reporté(s) au prochain passage." % (len(digest) - len(batch)))

    # 6. Sources injoignables depuis longtemps
    for name, health in state["health"].items():
        if health["fails"] >= FAIL_ALERT_AFTER and not health["alerted"]:
            hours = round(health["fails"] * 20 / 60)
            if sender.send("<b>Source injoignable</b>\n%s ne répond plus depuis environ %d h. "
                           "Vérifier l'URL du flux dans cyber_watch.py." % (esc(name), hours)):
                health["alerted"] = True

    save_state(state_path, state, now)
    log("[+] Terminé : %d message(s) envoyé(s)." % sender.count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
