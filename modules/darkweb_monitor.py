"""Dark web threat monitoring via clearnet aggregators and optional Tor.

Zero-cost monitoring of ransomware leak sites, dark web paste sites,
and underground forums using public clearnet mirrors and APIs.

Optional: Direct .onion access via Tor SOCKS proxy.
"""

import json
import logging
import re
import hashlib
from datetime import datetime, timezone, timedelta

import requests

from modules.config import FEED_CUTOFF_DAYS

_SESSION = None
_TOR_SESSION = None

# Clearnet sources that aggregate dark web intel (free, no API key)
DARKWEB_SOURCES = [
    {
        "name": "threatfox",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "type": "api_json",
        "parser": "_parse_threatfox",
        "description": "Recent IOCs from abuse.ch ThreatFox",
    },
    {
        "name": "ransomware.live",
        "url": "https://api.ransomware.live/recentvictims",
        "type": "api_json",
        "parser": "_parse_ransomware_live",
        "description": "Ransomware victim posts from leak sites",
    },
    {
        "name": "github-iocs",
        "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt",
        "type": "ioc_list",
        "parser": "_parse_c2_tracker",
        "description": "Active C2 server IPs",
    },
]

# Known ransomware group .onion sites (for optional Tor monitoring)
ONION_SITES = [
    {"group": "LockBit", "description": "LockBit ransomware leak site"},
    {"group": "BlackCat/ALPHV", "description": "ALPHV ransomware leak site"},
    {"group": "Cl0p", "description": "Cl0p ransomware leak site"},
    {"group": "8Base", "description": "8Base ransomware leak site"},
    {"group": "Akira", "description": "Akira ransomware leak site"},
]


def _get_session():
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
        _SESSION.headers.update({
            "User-Agent": "ThreatWatch/1.0 (Open Source Threat Intel)",
            "Accept": "application/json",
        })
    return _SESSION


def _get_tor_session():
    """Create a requests session routed through Tor SOCKS proxy."""
    global _TOR_SESSION
    if _TOR_SESSION is None:
        try:
            _TOR_SESSION = requests.Session()
            _TOR_SESSION.proxies = {
                "http": "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050",
            }
            _TOR_SESSION.headers.update({
                "User-Agent": "Mozilla/5.0",
            })
        except Exception as e:
            logging.warning(f"Tor session setup failed: {e}")
            return None
    return _TOR_SESSION


def check_tor_available():
    """Check if Tor SOCKS proxy is available."""
    try:
        session = _get_tor_session()
        if session is None:
            return False
        resp = session.get("https://check.torproject.org/api/ip", timeout=10)
        data = resp.json()
        is_tor = data.get("IsTor", False)
        if is_tor:
            logging.info(f"Tor connected. Exit IP: {data.get('IP', 'unknown')}")
        return is_tor
    except Exception:
        return False


def fetch_darkweb_intel():
    """Fetch threat intel from all clearnet dark web aggregators.

    Returns list of articles in the same format as the main pipeline.
    """
    all_articles = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=FEED_CUTOFF_DAYS)

    for source in DARKWEB_SOURCES:
        try:
            articles = _fetch_source(source, cutoff)
            all_articles.extend(articles)
            logging.info(
                f"Dark web: {len(articles)} items from {source['name']}"
            )
        except Exception as e:
            logging.warning(f"Dark web source {source['name']} failed: {e}")

    logging.info(f"Dark web monitoring: {len(all_articles)} total items")
    return all_articles


def _fetch_source(source, cutoff):
    """Fetch and parse a single dark web source."""
    session = _get_session()
    resp = session.get(source["url"], timeout=15)
    resp.raise_for_status()

    parser = globals().get(source["parser"])
    if parser is None:
        logging.warning(f"No parser for {source['name']}")
        return []

    return parser(resp, source, cutoff)


def _parse_ransomware_live(resp, source, cutoff):
    """Parse ransomware.live recent victims API."""
    articles = []
    try:
        data = resp.json()
        if not isinstance(data, list):
            return []

        for victim in data[:100]:  # Cap at 100
            name = victim.get("victim", victim.get("post_title", "Unknown"))
            group = victim.get("group_name", "Unknown")
            discovered = victim.get("discovered", victim.get("published", ""))
            url = victim.get("post_url", victim.get("website", ""))
            country = victim.get("country", "")

            # Parse date
            pub_dt = _parse_date(discovered)
            if pub_dt and pub_dt < cutoff:
                continue

            title = f"{group} ransomware: new victim '{name}'"
            if country:
                title += f" ({country})"

            article_hash = hashlib.sha256(
                (title + (url or name)).encode()
            ).hexdigest()

            articles.append({
                "title": title,
                "link": url if url and url.startswith("http") else f"https://ransomware.live/#/victims",
                "published": discovered or datetime.now(timezone.utc).isoformat(),
                "summary": (
                    f"Ransomware group {group} posted new victim '{name}' "
                    f"on their dark web leak site. "
                    f"{'Country: ' + country + '. ' if country else ''}"
                    f"Source: ransomware.live dark web monitoring."
                ),
                "hash": article_hash,
                "source": "darkweb:ransomware.live",
                "feed_region": _country_to_region(country),
                "darkweb": True,
                "darkweb_group": group,
                "darkweb_source": "ransomware.live",
            })
    except (json.JSONDecodeError, KeyError) as e:
        logging.warning(f"ransomware.live parse error: {e}")

    return articles


def _parse_threatfox(resp, source, cutoff):
    """Parse ThreatFox recent IOCs from abuse.ch."""
    articles = []
    try:
        data = resp.json()
        if not isinstance(data, dict):
            return []

        # Group IOCs by malware family for summary articles
        malware_groups = {}
        for _ioc_id, entries in list(data.items())[:500]:
            if not isinstance(entries, list):
                continue
            for entry in entries:
                malware = entry.get("malware_printable", "Unknown")
                first_seen = entry.get("first_seen_utc", "")
                pub_dt = _parse_date(first_seen)
                if pub_dt and pub_dt < cutoff:
                    continue
                if malware not in malware_groups:
                    malware_groups[malware] = {
                        "iocs": [],
                        "threat_type": entry.get("threat_type", ""),
                        "first_seen": first_seen,
                    }
                if len(malware_groups[malware]["iocs"]) < 10:
                    malware_groups[malware]["iocs"].append({
                        "value": entry.get("ioc_value", ""),
                        "type": entry.get("ioc_type", ""),
                    })

        # Create one article per malware family (cap at 20)
        for malware, info in list(malware_groups.items())[:20]:
            ioc_count = len(info["iocs"])
            sample_iocs = ", ".join(
                i["value"] for i in info["iocs"][:5]
            )
            title = (
                f"ThreatFox: {malware} — "
                f"{ioc_count} new IOC{'s' if ioc_count != 1 else ''} detected"
            )
            article_hash = hashlib.sha256(
                (title + info["first_seen"]).encode()
            ).hexdigest()

            articles.append({
                "title": title,
                "link": f"https://threatfox.abuse.ch/browse/malware/{malware.lower().replace(' ', '-')}/",
                "published": info["first_seen"] or datetime.now(timezone.utc).isoformat(),
                "summary": (
                    f"abuse.ch ThreatFox reports new indicators of compromise "
                    f"for {malware} ({info['threat_type']}). "
                    f"Sample IOCs: {sample_iocs}. "
                    f"Use these indicators for detection and blocking."
                ),
                "hash": article_hash,
                "source": "darkweb:threatfox",
                "feed_region": "Global",
                "darkweb": True,
                "darkweb_group": malware,
                "darkweb_source": "threatfox",
            })
    except (json.JSONDecodeError, KeyError) as e:
        logging.warning(f"ThreatFox parse error: {e}")

    return articles


def _parse_c2_tracker(resp, source, cutoff):
    """Parse C2-Tracker active C2 server list."""
    articles = []
    try:
        lines = resp.text.strip().split("\n")
        # Only report if there's a significant list
        ip_count = len([l for l in lines if l.strip() and not l.startswith("#")])

        if ip_count > 0:
            article_hash = hashlib.sha256(
                f"c2-tracker-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}".encode()
            ).hexdigest()

            # Extract sample IPs for the summary
            sample_ips = [l.strip() for l in lines if l.strip() and not l.startswith("#")][:10]

            articles.append({
                "title": f"C2 Tracker: {ip_count} active command & control servers detected",
                "link": "https://github.com/montysecurity/C2-Tracker",
                "published": datetime.now(timezone.utc).isoformat(),
                "summary": (
                    f"Open-source C2 server tracking identifies {ip_count} active "
                    f"command and control servers. Sample IPs: {', '.join(sample_ips)}. "
                    f"These indicators can be used for network-level blocking and detection."
                ),
                "hash": article_hash,
                "source": "darkweb:c2-tracker",
                "feed_region": "Global",
                "darkweb": True,
                "darkweb_source": "c2-tracker",
            })
    except Exception as e:
        logging.warning(f"C2-Tracker parse error: {e}")

    return articles


def _parse_date(date_str):
    """Try to parse various date formats."""
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(date_str[:19], fmt[:len(date_str)])
            return dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def _country_to_region(country):
    """Map country name to feed region."""
    if not country:
        return "Global"

    country_lower = country.lower()
    na = {"usa", "us", "united states", "canada", "mexico"}
    emea = {
        "uk", "united kingdom", "germany", "france", "italy", "spain",
        "netherlands", "poland", "sweden", "norway", "finland", "denmark",
        "switzerland", "austria", "belgium", "ireland", "portugal",
        "czech republic", "romania", "hungary", "greece", "south africa",
    }
    mena = {
        "uae", "united arab emirates", "saudi arabia", "israel", "iran",
        "turkey", "egypt", "qatar", "kuwait", "bahrain", "jordan", "iraq",
    }
    apac = {
        "japan", "australia", "india", "singapore", "south korea", "china",
        "taiwan", "indonesia", "malaysia", "thailand", "vietnam", "philippines",
        "new zealand", "hong kong", "pakistan", "bangladesh",
    }
    latam = {
        "brazil", "argentina", "colombia", "chile", "peru", "mexico",
        "costa rica", "panama", "ecuador", "venezuela",
    }

    if country_lower in na:
        return "US"
    if country_lower in emea:
        return "Europe"
    if country_lower in mena:
        return "Middle East"
    if country_lower in apac:
        return "APAC"
    if country_lower in latam:
        return "LATAM"
    return "Global"
