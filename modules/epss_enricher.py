"""EPSS (Exploit Prediction Scoring System) enricher.

Fetches exploit probability scores from FIRST.org EPSS API and enriches
articles that contain CVE IDs with their EPSS percentile and probability.

EPSS answers: "How likely is this CVE to be exploited in the next 30 days?"
- Score 0.0-1.0 (probability of exploitation)
- Percentile 0-100 (relative rank among all CVEs)

Zero cost — EPSS API is free and unauthenticated.
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

import requests

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"

# Extract CVE IDs from article text
_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)

# Disk cache: EPSS data updates ONCE per day upstream, but the enricher ran a
# live API call every 10-minute pipeline tick. Worse, a FIRST.org outage
# returned {} silently and the run's articles lost exploit-probability
# context with no signal. 6h TTL matches the KEV enricher.
from modules.config import STATE_DIR as _STATE_DIR
_EPSS_CACHE_PATH = _STATE_DIR / "epss_cache.json"
_EPSS_CACHE_TTL_H = 6

_SESSION = None


def _get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
        _SESSION.headers.update({
            "User-Agent": "ThreatWatch/1.0 (EPSS Enrichment)",
            "Accept": "application/json",
        })
    return _SESSION


def _load_epss_cache() -> dict:
    try:
        if _EPSS_CACHE_PATH.exists():
            return json.loads(_EPSS_CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return {"cached_at": None, "scores": {}}


def _save_epss_cache(cache: dict) -> None:
    try:
        from modules.utils import write_json_atomic
        write_json_atomic(_EPSS_CACHE_PATH, cache, ensure_ascii=False)
    except OSError as e:
        logger.debug("EPSS cache write failed: %s", e)


def _cache_fresh(cache: dict) -> bool:
    stamp = cache.get("cached_at")
    if not isinstance(stamp, str):
        return False
    try:
        cached_at = datetime.fromisoformat(stamp)
    except ValueError:
        return False
    age_h = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600
    return age_h < _EPSS_CACHE_TTL_H


def _fetch_epss_batch(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch EPSS scores for a batch of CVE IDs, with a 6h disk cache.

    Cache-first for CVEs already scored within the TTL; only cache misses
    hit the API. On API failure, stale cached scores are served (with a
    warning) rather than silently dropping enrichment for the run.
    Returns {cve_id: {"epss_score": float, "epss_percentile": float}}.
    """
    if not cve_ids:
        return {}

    cache = _load_epss_cache()
    fresh = _cache_fresh(cache)
    cached_scores = cache.get("scores", {})
    results = {}
    to_fetch = []
    for cve in cve_ids:
        if fresh and cve in cached_scores:
            results[cve] = cached_scores[cve]
        else:
            to_fetch.append(cve)
    if not to_fetch:
        return results

    # API accepts comma-separated CVE IDs (max ~100 per request)
    session = _get_session()
    fetched_any = False

    # Batch in chunks of 100
    for i in range(0, len(to_fetch), 100):
        chunk = to_fetch[i:i + 100]
        try:
            resp = session.get(
                EPSS_API_URL,
                params={"cve": ",".join(chunk)},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()

            for entry in data.get("data", []):
                cve_id = entry.get("cve", "").upper()
                if cve_id:
                    results[cve_id] = {
                        "epss_score": float(entry.get("epss", 0)),
                        "epss_percentile": float(entry.get("percentile", 0)),
                    }
                    fetched_any = True
        except Exception as e:
            logger.warning(f"EPSS: batch fetch failed for {len(chunk)} CVEs: {e}")
            # Serve stale cached scores for this chunk rather than silently
            # losing enrichment — and say so.
            stale_hits = [c for c in chunk if c in cached_scores]
            if stale_hits:
                logger.warning(
                    "EPSS: serving %d stale cached score(s) after API failure",
                    len(stale_hits),
                )
                for c in stale_hits:
                    results[c] = cached_scores[c]

    if fetched_any:
        merged = {**cached_scores, **{k: v for k, v in results.items()}}
        _save_epss_cache({
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "scores": merged,
        })

    return results


def _extract_cve_ids(article: dict) -> list[str]:
    """Extract CVE IDs from article title, summary, and cve_id field."""
    cves = set()

    # Direct cve_id field (from NVD fetcher)
    if article.get("cve_id"):
        cves.add(article["cve_id"].upper())

    # Scan title and summary for CVE mentions
    for field in ("title", "summary", "translated_title"):
        text = article.get(field, "")
        if text:
            for match in _CVE_RE.findall(text):
                cves.add(match.upper())

    return sorted(cves)


def _epss_risk_label(score: float) -> str:
    """Human-readable risk label from EPSS score."""
    if score >= 0.5:
        return "VERY HIGH"
    if score >= 0.1:
        return "HIGH"
    if score >= 0.01:
        return "MODERATE"
    return "LOW"


def enrich_articles_with_epss(articles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enrich articles containing CVE IDs with EPSS scores.

    Adds to each matching article:
    - epss_scores: [{cve_id, epss_score, epss_percentile, risk_label}]
    - epss_max_score: highest EPSS score among all CVEs in the article
    - epss_risk: risk label for the highest EPSS score
    """
    # Collect all CVE IDs across all articles
    article_cves = []
    all_cves = set()
    for article in articles:
        cves = _extract_cve_ids(article)
        article_cves.append(cves)
        all_cves.update(cves)

    if not all_cves:
        logger.info("EPSS: no CVE IDs found in articles, skipping.")
        return articles

    logger.info(f"EPSS: fetching scores for {len(all_cves)} unique CVEs")
    epss_data = _fetch_epss_batch(sorted(all_cves))
    logger.info(f"EPSS: got scores for {len(epss_data)} CVEs")

    # Enrich articles
    enriched_count = 0
    enriched = []
    for article, cves in zip(articles, article_cves):
        if not cves:
            enriched.append(article)
            continue

        scores = []
        for cve_id in cves:
            data = epss_data.get(cve_id)
            if data:
                scores.append({
                    "cve_id": cve_id,
                    "epss_score": data["epss_score"],
                    "epss_percentile": data["epss_percentile"],
                    "risk_label": _epss_risk_label(data["epss_score"]),
                })

        if scores:
            max_entry = max(scores, key=lambda s: s["epss_score"])
            article = {
                **article,
                "epss_scores": scores,
                "epss_max_score": max_entry["epss_score"],
                "epss_risk": max_entry["risk_label"],
            }
            enriched_count += 1

        enriched.append(article)

    logger.info(f"EPSS: enriched {enriched_count} articles with exploit prediction scores")
    return enriched
