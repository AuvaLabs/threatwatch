"""NVD (National Vulnerability Database) CVE fetcher.

Fetches recent CVEs from NVD API 2.0, filters for critical/high severity,
and produces articles for the pipeline. Zero cost — NVD API is free
(rate-limited to ~5 req/30s without API key, 50 req/30s with key).

Env vars:
    NVD_API_KEY (optional) — increases rate limit from 5 to 50 req/30s
"""

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from modules.config import FEED_CUTOFF_DAYS, STATE_DIR
from modules.provider_health import record_failure, record_success

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_STATE_FILE = STATE_DIR / "nvd_last_fetch.json"

# Only create articles for CVEs at or above this severity
_MIN_CVSS_SCORE = 7.0  # HIGH and CRITICAL

# Rate limit: at most once per 10 minutes
_MIN_FETCH_INTERVAL = 600
_RETRY_ATTEMPTS = max(1, int(os.getenv("NVD_RETRY_ATTEMPTS", "3")))
_RETRY_BACKOFF_SECONDS = max(0.0, float(os.getenv("NVD_RETRY_BACKOFF_SECONDS", "1")))
_CACHE_MAX_AGE_HOURS = max(1, int(os.getenv("NVD_CACHE_MAX_AGE_HOURS", "24")))

_SESSION = None


def _get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
        headers = {
            "User-Agent": "ThreatWatch/1.0 (CVE Monitor)",
            "Accept": "application/json",
        }
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        _SESSION.headers.update(headers)
    return _SESSION


def _load_state() -> dict:
    if NVD_STATE_FILE.exists():
        try:
            return json.loads(NVD_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_state(state: dict) -> None:
    NVD_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    NVD_STATE_FILE.write_text(json.dumps(state), encoding="utf-8")


def _should_fetch() -> bool:
    state = _load_state()
    last_fetch = state.get("last_fetch_utc")
    if not last_fetch:
        return True
    try:
        last_dt = datetime.fromisoformat(last_fetch)
        elapsed = (datetime.now(timezone.utc) - last_dt).total_seconds()
        return elapsed >= _MIN_FETCH_INTERVAL
    except Exception:
        return True


def _request_nvd(session: requests.Session, params: dict[str, Any]) -> requests.Response:
    retryable_statuses = {429, 500, 502, 503, 504}
    last_error: requests.RequestException | None = None
    for attempt in range(_RETRY_ATTEMPTS):
        try:
            response = session.get(NVD_API_URL, params=params, timeout=20)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as error:
            status = getattr(error.response, "status_code", None)
            if status not in retryable_statuses:
                raise
            last_error = error
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as error:
            last_error = error
        if attempt + 1 < _RETRY_ATTEMPTS:
            time.sleep(_RETRY_BACKOFF_SECONDS * (2 ** attempt))
    if last_error is None:
        raise requests.exceptions.RequestException("NVD request failed")
    raise last_error


def _load_cached_articles() -> list[dict[str, Any]]:
    state = _load_state()
    try:
        fetched_at = datetime.fromisoformat(
            str(state["last_success_utc"]).replace("Z", "+00:00")
        )
        if fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - fetched_at
    except (KeyError, TypeError, ValueError):
        return []
    articles = state.get("articles")
    if age > timedelta(hours=_CACHE_MAX_AGE_HOURS) or not isinstance(articles, list):
        return []
    return [dict(article) for article in articles if isinstance(article, dict)]


def _provider_error_code(error: Exception) -> str:
    if isinstance(error, requests.exceptions.Timeout):
        return "request_timeout"
    if isinstance(error, requests.exceptions.ConnectionError):
        return "connection_error"
    if isinstance(error, requests.exceptions.HTTPError):
        status = getattr(error.response, "status_code", None)
        return f"http_{status}" if isinstance(status, int) else "http_error"
    return "provider_error"


def _cvss_score(vuln: dict) -> tuple[float, str]:
    """Extract highest CVSS score and vector from a CVE record."""
    metrics = vuln.get("metrics", {})

    # Try CVSS 3.1 first, then 3.0, then 2.0
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore", 0.0), data.get("vectorString", "")

    v2 = metrics.get("cvssMetricV2", [])
    if v2:
        data = v2[0].get("cvssData", {})
        return data.get("baseScore", 0.0), data.get("vectorString", "")

    return 0.0, ""


def _severity_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def fetch_nvd_cves() -> list[dict[str, Any]]:
    """Fetch recent high/critical CVEs from NVD API 2.0.

    Returns articles in the standard pipeline format.
    """
    if not _should_fetch():
        logger.info(
            "NVD: internal 10-minute fetch interval has not elapsed; skipping this run."
        )
        return []

    now = datetime.now(timezone.utc)
    # Fetch CVEs published in the last FEED_CUTOFF_DAYS
    pub_start = (now - timedelta(days=min(FEED_CUTOFF_DAYS, 7))).strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "cvssV3Severity": "HIGH",  # HIGH + CRITICAL
        "resultsPerPage": 100,
    }

    articles = []
    try:
        session = _get_session()
        resp = _request_nvd(session, params)
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        logger.info(f"NVD: fetched {len(vulns)} CVEs (HIGH+CRITICAL, last {FEED_CUTOFF_DAYS}d)")

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            score, vector = _cvss_score(cve)
            if score < _MIN_CVSS_SCORE:
                continue

            severity = _severity_label(score)
            published = cve.get("published", now.isoformat())

            # Extract description (English preferred)
            descriptions = cve.get("descriptions", [])
            desc_en = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else "",
            )

            # Extract affected products from CPE matches
            affected = []
            configs = cve.get("configurations", [])
            for cfg in configs[:3]:
                for node in cfg.get("nodes", [])[:3]:
                    for match in node.get("cpeMatch", [])[:5]:
                        criteria = match.get("criteria", "")
                        # Parse vendor:product from CPE 2.3 string
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3].replace("_", " ").title()
                            product = parts[4].replace("_", " ").title()
                            affected.append(f"{vendor} {product}")

            affected_str = ", ".join(set(affected[:5])) if affected else "multiple products"

            # Extract references
            refs = cve.get("references", [])
            ref_url = refs[0]["url"] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            # Extract CWE
            weaknesses = cve.get("weaknesses", [])
            cwe_ids = []
            for w in weaknesses:
                for d in w.get("description", []):
                    if d.get("value", "").startswith("CWE-"):
                        cwe_ids.append(d["value"])

            title = f"{cve_id}: {severity} ({score}) — {desc_en[:120]}"
            if len(desc_en) > 120:
                title = title[:title.rfind(" ", 0, 150)] + "..."

            summary = (
                f"{cve_id} (CVSS {score} {severity}): {desc_en[:400]} "
                f"Affected: {affected_str}. "
                f"{'CWE: ' + ', '.join(cwe_ids) + '. ' if cwe_ids else ''}"
                f"Vector: {vector}"
            )

            article_hash = hashlib.sha256(cve_id.encode()).hexdigest()

            articles.append({
                "title": title,
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": published,
                "summary": summary,
                "hash": article_hash,
                "source": "nvd:cve",
                "feed_region": "Global",
                "category": "Vulnerability Disclosure",
                "confidence": 95,
                "is_cyber_attack": True,
                "cve_id": cve_id,
                "cvss_score": score,
                "cvss_severity": severity,
                "cvss_vector": vector,
                "cwe_ids": cwe_ids,
                "affected_products": list(set(affected[:10])),
                "ref_url": ref_url,
            })

        _save_state({
            "last_fetch_utc": now.isoformat(),
            "last_success_utc": now.isoformat(),
            "articles": articles,
        })
        record_success("nvd", item_count=len(articles))

    except requests.exceptions.RequestException as e:
        record_failure("nvd", _provider_error_code(e), cooldown_seconds=0)
        cached = _load_cached_articles()
        logger.warning(
            "NVD: request failed after %d attempts; using %d cached items: %s",
            _RETRY_ATTEMPTS,
            len(cached),
            e,
        )
        return cached
    except Exception as e:
        record_failure("nvd", "provider_error", cooldown_seconds=0)
        cached = _load_cached_articles()
        logger.warning("NVD: fetch failed; using %d cached items: %s", len(cached), e)
        return cached

    return articles
