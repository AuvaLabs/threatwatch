"""CISA KEV (Known Exploited Vulnerabilities) enricher.

Fetches the CISA KEV catalog and flags articles whose CVEs appear on the list.

KEV answers a different question than EPSS:
- EPSS: "How likely is this CVE to be exploited in the next 30 days?" (probabilistic)
- KEV:  "Is this CVE confirmed to be exploited in the wild RIGHT NOW?" (factual, per CISA)

A KEV listing is the most authoritative "act now" signal a defender can get,
because federal agencies are mandated to remediate KEV entries by the due date.

Zero cost — the catalog is a free, unauthenticated JSON feed.
Cached locally with a 6-hour TTL to stay friendly to CISA infrastructure.
"""

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import requests

from modules.config import STATE_DIR

logger = logging.getLogger(__name__)

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_PATH: Path = STATE_DIR / "kev_catalog.json"
KEV_CACHE_TTL_SECONDS = 6 * 60 * 60  # 6 hours

_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)

_SESSION: requests.Session | None = None


def _get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
        _SESSION.headers.update({
            "User-Agent": "ThreatWatch/1.0 (CISA KEV Enrichment)",
            "Accept": "application/json",
        })
    return _SESSION


def _cache_is_fresh(path: Path, ttl_seconds: int) -> bool:
    if not path.exists():
        return False
    age = time.time() - path.stat().st_mtime
    return age < ttl_seconds


def _load_cached_catalog() -> dict | None:
    if not KEV_CACHE_PATH.exists():
        return None
    try:
        with open(KEV_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"KEV: failed to read cache at {KEV_CACHE_PATH}: {e}")
        return None


def _save_cached_catalog(payload: dict) -> None:
    try:
        KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(KEV_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(payload, f)
    except IOError as e:
        logger.warning(f"KEV: failed to write cache at {KEV_CACHE_PATH}: {e}")


def fetch_kev_catalog(force_refresh: bool = False) -> dict[str, dict]:
    """Return KEV catalog as {cve_id: kev_entry}.

    Uses a 6h on-disk cache. On network failure falls back to the cached copy
    even if stale, so a CISA outage cannot wipe out enrichment.
    """
    if not force_refresh and _cache_is_fresh(KEV_CACHE_PATH, KEV_CACHE_TTL_SECONDS):
        cached = _load_cached_catalog()
        if cached:
            return cached

    try:
        session = _get_session()
        resp = session.get(KEV_FEED_URL, timeout=15)
        resp.raise_for_status()
        raw = resp.json()
    except Exception as e:
        logger.warning(f"KEV: live fetch failed ({e}); falling back to stale cache")
        return _load_cached_catalog() or {}

    indexed: dict[str, dict] = {}
    for entry in raw.get("vulnerabilities", []):
        cve_id = (entry.get("cveID") or "").upper()
        if not cve_id:
            continue
        indexed[cve_id] = {
            "cve_id": cve_id,
            "vendor": entry.get("vendorProject", ""),
            "product": entry.get("product", ""),
            "vulnerability_name": entry.get("vulnerabilityName", ""),
            "date_added": entry.get("dateAdded", ""),
            "due_date": entry.get("dueDate", ""),
            "required_action": entry.get("requiredAction", ""),
            "ransomware_use": (entry.get("knownRansomwareCampaignUse") or "Unknown"),
        }

    _save_cached_catalog(indexed)
    logger.info(f"KEV: fetched {len(indexed)} entries from CISA")
    return indexed


def _extract_cve_ids(article: dict) -> list[str]:
    """Extract CVE IDs from article fields. Mirrors epss_enricher for consistency."""
    cves: set[str] = set()
    if article.get("cve_id"):
        cves.add(str(article["cve_id"]).upper())
    for cve in article.get("cve_ids", []) or []:
        cves.add(str(cve).upper())
    for field in ("title", "summary", "translated_title"):
        text = article.get(field) or ""
        for match in _CVE_RE.findall(text):
            cves.add(match.upper())
    return sorted(cves)


def enrich_articles_with_kev(
    articles: list[dict[str, Any]],
    catalog: dict[str, dict] | None = None,
) -> list[dict[str, Any]]:
    """Flag articles whose CVEs appear in the CISA KEV catalog.

    Adds to each matching article:
    - kev_listed: True
    - kev_entries: list of matched KEV entries (vendor, product, date_added, ...)
    - kev_min_date_added: earliest date_added among matched CVEs (string)
    - kev_ransomware_use: "Known" if any matched CVE has knownRansomwareCampaignUse=Known
    """
    if catalog is None:
        catalog = fetch_kev_catalog()
    if not catalog:
        return articles

    enriched_count = 0
    out = []
    for article in articles:
        cves = _extract_cve_ids(article)
        if not cves:
            out.append(article)
            continue

        matches = [catalog[c] for c in cves if c in catalog]
        if not matches:
            out.append(article)
            continue

        dates = [m["date_added"] for m in matches if m.get("date_added")]
        ransomware = any(m.get("ransomware_use") == "Known" for m in matches)

        out.append({
            **article,
            "kev_listed": True,
            "kev_entries": matches,
            "kev_min_date_added": min(dates) if dates else "",
            "kev_ransomware_use": "Known" if ransomware else "Unknown",
        })
        enriched_count += 1

    logger.info(f"KEV: flagged {enriched_count} articles as actively exploited (CISA KEV)")
    return out
