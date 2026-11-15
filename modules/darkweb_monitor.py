"""Dark web threat monitoring via clearnet aggregators and optional Tor.

Zero-cost monitoring of ransomware leak sites, dark web paste sites,
and underground forums using public clearnet mirrors and APIs.

Optional: Direct .onion access via Tor SOCKS proxy.
"""

import json
import logging
import os
import re
import hashlib
from typing import Any

logger = logging.getLogger(__name__)
from datetime import datetime, timezone, timedelta

import requests
from urllib.parse import quote

from modules.config import FEED_CUTOFF_DAYS
from modules.provider_health import (
    is_suspended,
    record_disabled,
    record_failure as record_provider_failure,
    record_success as record_provider_success,
)
from modules.url_resolver import is_clearnet_url

_SESSION = None
_TOR_SESSION = None
_PROVIDER_FAILURE_COOLDOWN_SECONDS = max(
    0, int(os.getenv("DARKWEB_PROVIDER_FAILURE_COOLDOWN_SECONDS", "900"))
)
_RANSOMWARE_LIVE_FAILURE_COOLDOWN_SECONDS = max(
    0, int(os.getenv("RANSOMWARE_LIVE_FAILURE_COOLDOWN_SECONDS", "21600"))
)

# Clearnet sources that aggregate dark web intel (free, no API key)
DARKWEB_SOURCES = [
    {
        "name": "threatfox",
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "type": "api_json",
        "parser": "_parse_threatfox",
        "description": "Recent IOCs from abuse.ch ThreatFox",
        "method": "POST",
        "auth_env": "THREATFOX_AUTH_KEY",
        "payload": {"query": "get_iocs", "days": 7},
    },
    {
        "name": "ransomware.live",
        "url": "https://api.ransomware.live/recentvictims",
        "type": "api_json",
        "parser": "_parse_ransomware_live",
        "description": "Ransomware victim posts from leak sites",
        "failure_cooldown_seconds": _RANSOMWARE_LIVE_FAILURE_COOLDOWN_SECONDS,
    },
    # C2-Tracker (montysecurity) removed 2026-04-21: repo archived.
    # Feodo Tracker (abuse.ch) evaluated as replacement but has <5 active IPs.
    # C2 signal now comes from ThreatFox IOCs above (covers C2 indicators
    # alongside other malware IOCs). Re-evaluate if a high-volume C2 IP feed
    # becomes available.
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
        name = str(source["name"])
        auth_env = str(source.get("auth_env") or "")
        if auth_env and not os.getenv(auth_env, "").strip():
            record_disabled(name, "credential_not_configured")
            logger.info("Dark web source %s disabled: %s is not configured", name, auth_env)
            continue
        if is_suspended(name):
            logger.info("Dark web source %s suspended until its next health probe", name)
            continue
        try:
            articles = _fetch_source(source, cutoff)
            all_articles.extend(articles)
            record_provider_success(name, item_count=len(articles))
            logger.info(
                "Dark web: %d items from %s", len(articles), name
            )
        except Exception as e:
            cooldown = max(
                0,
                int(source.get(
                    "failure_cooldown_seconds",
                    _PROVIDER_FAILURE_COOLDOWN_SECONDS,
                )),
            )
            record_provider_failure(
                name,
                _provider_error_code(e),
                cooldown_seconds=cooldown,
            )
            logger.warning("Dark web source %s failed: %s", name, e)

    logger.info(f"Dark web monitoring: {len(all_articles)} total items")
    return all_articles


def _provider_error_code(error: Exception) -> str:
    message = str(error).lower()
    if isinstance(error, requests.exceptions.SSLError):
        if "certificate has expired" in message:
            return "tls_certificate_expired"
        return "tls_validation_error"
    if isinstance(error, requests.exceptions.Timeout):
        return "request_timeout"
    if isinstance(error, requests.exceptions.HTTPError):
        response = getattr(error, "response", None)
        status = getattr(response, "status_code", None)
        return f"http_{status}" if isinstance(status, int) else "http_error"
    if isinstance(error, requests.exceptions.ConnectionError):
        return "connection_error"
    return "provider_error"


def _fetch_source(source: dict[str, Any], cutoff: datetime) -> list[dict[str, Any]]:
    """Fetch and parse a single dark web source."""
    session = _get_session()
    if source.get("method") == "POST":
        auth_env = str(source.get("auth_env") or "")
        auth_key = os.getenv(auth_env, "").strip() if auth_env else ""
        if auth_env and not auth_key:
            logger.info("Dark web source %s disabled: %s is not configured", source["name"], auth_env)
            return []
        headers = {"Auth-Key": auth_key} if auth_key else None
        resp = session.post(
            source["url"],
            json=source.get("payload") or {},
            headers=headers,
            timeout=15,
        )
    else:
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

            # Parse date. Items with a missing/unparseable discovery date are
            # dropped outright: the old fallback stamped them published=now(),
            # which both bypassed the cutoff filter and presented undated
            # backfill as a fresh incident.
            pub_dt = _parse_date(discovered)
            if pub_dt is None:
                logger.debug(
                    "ransomware.live victim %r has no parseable date (%r) — skipped",
                    name, discovered,
                )
                continue
            if pub_dt < cutoff:
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
                "published": discovered,
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

        if "query_status" in data and isinstance(data.get("data"), list):
            if data.get("query_status") != "ok" or not isinstance(data.get("data"), list):
                return []
            raw_entries = data["data"][:500]
        else:
            raw_entries = [
                entry
                for entries in list(data.values())[:500]
                if isinstance(entries, list)
                for entry in entries
                if isinstance(entry, dict)
            ]

        # Group IOCs by malware family for summary articles
        malware_groups = {}
        for entry in raw_entries:
            malware = entry.get("malware_printable") or entry.get("malware") or "Unknown"
            first_seen = entry.get("first_seen_utc") or entry.get("first_seen") or ""
            # Undated IOC entries are dropped: the old published=now()
            # fallback fabricated freshness for them downstream.
            pub_dt = _parse_date(first_seen)
            if pub_dt is None or pub_dt < cutoff:
                continue
            if malware not in malware_groups:
                malware_groups[malware] = {
                    "iocs": [],
                    "malware_id": entry.get("malware") or "",
                    "threat_type": entry.get("threat_type", ""),
                    "first_seen": first_seen,
                }
            if len(malware_groups[malware]["iocs"]) < 10:
                malware_groups[malware]["iocs"].append({
                    "value": entry.get("ioc_value") or entry.get("ioc") or "",
                    "type": entry.get("ioc_type", ""),
                })

        # Create one article per malware family (cap at 20)
        # Hash includes today's date so each family produces exactly ONE article
        # per calendar day (prevents duplicate titles across pipeline runs)
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        for malware, info in list(malware_groups.items())[:20]:
            ioc_count = len(info["iocs"])
            malware_id = str(info.get("malware_id") or "").strip()
            browse_link = "https://threatfox.abuse.ch/browse/"
            if malware_id and malware_id.lower() != "unknown":
                browse_link = (
                    "https://threatfox.abuse.ch/browse/malware/"
                    f"{quote(malware_id, safe='._-')}/"
                )
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
                "link": browse_link,
                "published": info["first_seen"],
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
                "structured_iocs": _threatfox_iocs(info["iocs"]),
            })
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"ThreatFox parse error: {e}")

    return articles


def _threatfox_iocs(entries: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Normalize ThreatFox's typed records without losing provider provenance."""
    from modules.ioc_extractor import extract_iocs

    type_map = {
        "url": "urls",
        "domain": "domains",
        "hostname": "domains",
        "ip": "ipv4",
        "ip:port": "ipv4",
        "sha256_hash": "sha256",
        "sha1_hash": "sha1",
        "md5_hash": "md5",
    }
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        raw_value = str(entry.get("value") or "").strip()
        expected = type_map.get(str(entry.get("type") or "").casefold())
        if not raw_value or expected is None:
            continue
        extracted = extract_iocs(raw_value)
        values = extracted.get(expected) or []
        for value in values:
            key = (expected, value.casefold())
            if key in seen:
                continue
            seen.add(key)
            normalized.append({
                "type": expected,
                "value": value,
                "provider": "threatfox",
            })
    return normalized


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
