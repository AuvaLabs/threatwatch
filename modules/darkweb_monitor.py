"""Dark web threat monitoring via clearnet aggregators and optional Tor.

Zero-cost monitoring of ransomware leak sites, dark web paste sites,
and underground forums using public clearnet mirrors and APIs.

Optional: Direct .onion access via Tor SOCKS proxy.
"""

import json
import logging
import re
import hashlib
from typing import Any

logger = logging.getLogger(__name__)
from datetime import datetime, timezone, timedelta

import requests

from modules.config import FEED_CUTOFF_DAYS
from modules.url_resolver import is_clearnet_url

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
    # Disabled 2026-04-21: montysecurity/C2-Tracker repo archived, data files removed.
    # {
    #     "name": "github-iocs",
    #     "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt",
    #     "type": "ioc_list",
    #     "parser": "_parse_c2_tracker",
    #     "description": "Active C2 server IPs",
    # },
]

# Known ransomware group .onion sites (for optional Tor monitoring)
ONION_SITES = [
    {"group": "LockBit", "description": "LockBit ransomware leak site"},
    {"group": "BlackCat/ALPHV", "description": "ALPHV ransomware leak site"},
    {"group": "Cl0p", "description": "Cl0p ransomware leak site"},
    {"group": "8Base", "description": "8Base ransomware leak site"},
    {"group": "Akira", "description": "Akira ransomware leak site"},
]


def _get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
        _SESSION.headers.update({
            "User-Agent": "ThreatWatch/1.0 (Open Source Threat Intel)",
            "Accept": "application/json",
        })
    return _SESSION


def _get_tor_session() -> requests.Session | None:
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
            logger.warning(f"Tor session setup failed: {e}")
            return None
    return _TOR_SESSION


def check_tor_available() -> bool:
    """Check if Tor SOCKS proxy is available."""
    try:
        session = _get_tor_session()
        if session is None:
            return False
        resp = session.get("https://check.torproject.org/api/ip", timeout=10)
        data = resp.json()
        is_tor = data.get("IsTor", False)
        if is_tor:
            logger.info(f"Tor connected. Exit IP: {data.get('IP', 'unknown')}")
        return is_tor
    except Exception:
        return False


def fetch_darkweb_intel() -> list[dict[str, Any]]:
    """Fetch threat intel from all clearnet dark web aggregators.

    Returns list of articles in the same format as the main pipeline.
    """
    all_articles = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=FEED_CUTOFF_DAYS)

    for source in DARKWEB_SOURCES:
        try:
            articles = _fetch_source(source, cutoff)
            all_articles.extend(articles)
            logger.info(
                f"Dark web: {len(articles)} items from {source['name']}"
            )
        except Exception as e:
            logger.warning(f"Dark web source {source['name']} failed: {e}")

    logger.info(f"Dark web monitoring: {len(all_articles)} total items")
    return all_articles


def _fetch_source(source: dict[str, Any], cutoff: datetime) -> list[dict[str, Any]]:
    """Fetch and parse a single dark web source."""
    session = _get_session()
    resp = session.get(source["url"], timeout=15)
    resp.raise_for_status()

    parser = globals().get(source["parser"])
    if parser is None:
        logger.warning(f"No parser for {source['name']}")
        return []

    return parser(resp, source, cutoff)


def _parse_ransomware_live(resp: requests.Response, source: dict[str, Any], cutoff: datetime) -> list[dict[str, Any]]:
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
                "link": url if is_clearnet_url(url) else "https://ransomware.live/#/victims",
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
        logger.warning(f"ransomware.live parse error: {e}")

    return articles


def _parse_threatfox(resp: requests.Response, source: dict[str, Any], cutoff: datetime) -> list[dict[str, Any]]:
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
        # Hash includes today's date so each family produces exactly ONE article
        # per calendar day (prevents duplicate titles across pipeline runs)
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
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
                (f"threatfox:{malware}:{today_str}").encode()
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
        logger.warning(f"ThreatFox parse error: {e}")

    return articles


def _parse_c2_tracker(resp: requests.Response, source: dict[str, Any], cutoff: datetime) -> list[dict[str, Any]]:
    """Parse C2-Tracker active C2 server list."""
    articles = []
    try:
        lines = resp.text.strip().split("\n")
        # Only report if there's a significant list
        ip_count = len([ln for ln in lines if ln.strip() and not ln.startswith("#")])

        if ip_count > 0:
            article_hash = hashlib.sha256(
                f"c2-tracker-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}".encode()
            ).hexdigest()

            # Extract sample IPs for the summary
            sample_ips = [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")][:10]

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
        logger.warning(f"C2-Tracker parse error: {e}")

    return articles


def _parse_date(date_str: str | None) -> datetime | None:
    """Thin wrapper over date_utils.parse_datetime — kept for call-site stability."""
    from modules.date_utils import parse_datetime
    return parse_datetime(date_str)


# ── Country/region lookup tables (module-level for efficiency) ────────────────
_ISO2_TO_REGION = {
    "us": "US", "ca": "US", "mx": "LATAM",
    "gb": "Europe", "uk": "Europe", "de": "Europe", "fr": "Europe",
    "it": "Europe", "es": "Europe", "nl": "Europe", "pl": "Europe",
    "se": "Europe", "no": "Europe", "fi": "Europe", "dk": "Europe",
    "ch": "Europe", "at": "Europe", "be": "Europe", "ie": "Europe",
    "pt": "Europe", "cz": "Europe", "ro": "Europe", "hu": "Europe",
    "gr": "Europe", "bg": "Europe", "hr": "Europe", "sk": "Europe",
    "si": "Europe", "lt": "Europe", "lv": "Europe", "ee": "Europe",
    "lu": "Europe", "cy": "Europe", "mt": "Europe", "al": "Europe",
    "rs": "Europe", "ua": "Europe", "ba": "Europe", "me": "Europe",
    "mk": "Europe", "md": "Europe", "by": "Europe", "za": "Europe",
    "ng": "Europe", "ke": "Europe", "et": "Europe", "gh": "Europe",
    "ae": "Middle East", "sa": "Middle East", "il": "Middle East",
    "ir": "Middle East", "tr": "Middle East", "eg": "Middle East",
    "qa": "Middle East", "kw": "Middle East", "bh": "Middle East",
    "jo": "Middle East", "iq": "Middle East", "lb": "Middle East",
    "om": "Middle East", "ye": "Middle East", "sy": "Middle East",
    "ps": "Middle East", "ly": "Middle East", "ma": "Middle East",
    "tn": "Middle East", "dz": "Middle East",
    "jp": "APAC", "au": "APAC", "in": "APAC", "sg": "APAC",
    "kr": "APAC", "cn": "APAC", "tw": "APAC", "id": "APAC",
    "my": "APAC", "th": "APAC", "vn": "APAC", "ph": "APAC",
    "nz": "APAC", "hk": "APAC", "pk": "APAC", "bd": "APAC",
    "lk": "APAC", "mm": "APAC", "kh": "APAC", "np": "APAC",
    "br": "LATAM", "ar": "LATAM", "co": "LATAM", "cl": "LATAM",
    "pe": "LATAM", "ec": "LATAM", "ve": "LATAM", "py": "LATAM",
    "uy": "LATAM", "bo": "LATAM", "cr": "LATAM", "pa": "LATAM",
    "gt": "LATAM", "hn": "LATAM", "sv": "LATAM", "ni": "LATAM",
    "do": "LATAM", "cu": "LATAM", "pr": "LATAM",
}

_NAME_TO_REGION = {}
for _name in ("usa", "united states", "canada"):
    _NAME_TO_REGION[_name] = "US"
for _name in (
    "united kingdom", "germany", "france", "italy", "spain",
    "netherlands", "poland", "sweden", "norway", "finland", "denmark",
    "switzerland", "austria", "belgium", "ireland", "portugal",
    "czech republic", "romania", "hungary", "greece", "bulgaria",
    "croatia", "slovakia", "slovenia", "serbia", "ukraine", "belarus",
    "south africa", "nigeria", "kenya", "ethiopia", "ghana",
    "russia", "russian federation",
):
    _NAME_TO_REGION[_name] = "Europe"
for _name in (
    "uae", "united arab emirates", "saudi arabia", "israel", "iran",
    "turkey", "egypt", "qatar", "kuwait", "bahrain", "jordan", "iraq",
    "lebanon", "oman", "yemen", "syria", "libya", "morocco",
    "tunisia", "algeria",
):
    _NAME_TO_REGION[_name] = "Middle East"
for _name in (
    "japan", "australia", "india", "singapore", "south korea", "china",
    "taiwan", "indonesia", "malaysia", "thailand", "vietnam", "philippines",
    "new zealand", "hong kong", "pakistan", "bangladesh", "sri lanka",
    "myanmar", "cambodia", "nepal",
):
    _NAME_TO_REGION[_name] = "APAC"
for _name in (
    "brazil", "argentina", "colombia", "chile", "peru", "mexico",
    "ecuador", "venezuela", "paraguay", "uruguay", "bolivia",
    "costa rica", "panama", "guatemala", "honduras", "el salvador",
    "nicaragua", "dominican republic", "cuba", "puerto rico",
):
    _NAME_TO_REGION[_name] = "LATAM"


def _country_to_region(country: str) -> str:
    """Map country name or ISO-2 code to feed region."""
    if not country:
        return "Global"
    key = country.lower().strip()
    if len(key) == 2:
        return _ISO2_TO_REGION.get(key, "Global")
    return _NAME_TO_REGION.get(key, "Global")
