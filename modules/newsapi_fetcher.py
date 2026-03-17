"""NewsAPI.org fetcher for cybersecurity news.

Fetches articles from newsapi.org using the /v2/everything endpoint.
Rate-limited to at most one call per NEWSAPI_INTERVAL seconds (default 1800)
so the free-tier 100 req/day limit is never exceeded.

Requires NEWSAPI_KEY in the environment / .env file.
"""
import hashlib
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from modules.config import STATE_DIR
from modules.url_resolver import is_clearnet_url

_LAST_CALL_FILE = STATE_DIR / "newsapi_last_call.txt"
_NEWSAPI_INTERVAL = int(os.getenv("NEWSAPI_INTERVAL", "1800"))  # 30 min default

# Cybersecurity search query — broad enough to catch diverse threat categories
_QUERY = (
    "cybersecurity OR ransomware OR \"data breach\" OR malware OR phishing "
    "OR \"zero-day\" OR vulnerability OR \"cyber attack\" OR APT OR \"threat actor\""
)

_ENDPOINT = "https://newsapi.org/v2/everything"
_TIMEOUT = 15
_PAGE_SIZE = 100


def _load_last_call() -> float:
    try:
        if _LAST_CALL_FILE.exists():
            return float(_LAST_CALL_FILE.read_text().strip())
    except Exception:
        pass
    return 0.0


def _save_last_call(ts: float) -> None:
    try:
        _LAST_CALL_FILE.parent.mkdir(parents=True, exist_ok=True)
        _LAST_CALL_FILE.write_text(str(ts))
    except Exception as e:
        logging.warning(f"NewsAPI: could not save last call timestamp: {e}")


def _normalize(article: dict) -> dict | None:
    """Convert a NewsAPI article dict to the internal article format."""
    title = (article.get("title") or "").strip()
    url = (article.get("url") or "").strip()
    if not title or title == "[Removed]":
        return None
    if not is_clearnet_url(url):
        return None

    published = article.get("publishedAt") or ""
    # Convert ISO 8601 to RFC 2822-style for compatibility with feed_fetcher date parsing
    # Keep as ISO — parsedate_to_datetime handles it via email.utils fallback anyway,
    # but the pipeline also accepts raw ISO strings via timestamp field.
    description = (article.get("description") or "").strip()
    source_name = (article.get("source") or {}).get("name") or "NewsAPI"

    article_hash = hashlib.sha256((title + url).encode()).hexdigest()

    return {
        "title": title,
        "link": url,
        "published": published,
        "summary": description,
        "hash": article_hash,
        "source": f"newsapi:{source_name}",
        "feed_region": "Global",
    }


def fetch_newsapi_articles() -> list[dict]:
    """Fetch cybersecurity articles from NewsAPI.

    Returns an empty list if:
    - NEWSAPI_KEY is not set
    - Rate limit window has not elapsed
    - Request fails
    """
    api_key = os.getenv("NEWSAPI_KEY")
    if not api_key:
        logging.debug("NewsAPI: NEWSAPI_KEY not set, skipping")
        return []

    now = time.time()
    last_call = _load_last_call()
    elapsed = now - last_call
    if elapsed < _NEWSAPI_INTERVAL:
        wait_min = (_NEWSAPI_INTERVAL - elapsed) / 60
        logging.debug(f"NewsAPI: rate limit active, {wait_min:.1f}m until next call")
        return []

    # Fetch articles published in the last 24 hours to avoid stale content
    from_dt = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    params = {
        "q": _QUERY,
        "language": "en",
        "sortBy": "publishedAt",
        "pageSize": _PAGE_SIZE,
        "from": from_dt,
        "apiKey": api_key,
    }

    try:
        resp = requests.get(_ENDPOINT, params=params, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logging.error(f"NewsAPI: request failed: {e}")
        return []

    if data.get("status") != "ok":
        logging.warning(f"NewsAPI: non-ok response: {data.get('message', data.get('status'))}")
        return []

    _save_last_call(now)

    raw_articles = data.get("articles") or []
    articles = [a for a in (_normalize(r) for r in raw_articles) if a]
    logging.info(f"NewsAPI: fetched {len(articles)} articles ({len(raw_articles)} raw)")
    return articles
