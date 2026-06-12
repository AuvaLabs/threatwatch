import feedparser
import hashlib
import logging
import threading
import requests
from typing import Any

logger = logging.getLogger(__name__)
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import parsedate_to_datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from modules.config import FEED_CUTOFF_DAYS
from modules.url_resolver import resolve_original_url, is_clearnet_url
from modules.feed_health import record_fetch
from modules.deduplicator import normalize_url

def _parse_article_date(date_str: str) -> datetime | None:
    """Thin wrapper over date_utils.parse_datetime — call-site stability only."""
    from modules.date_utils import parse_datetime
    return parse_datetime(date_str)


_FEED_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
}

# (connect, read) — connect fails fast; the read budget is generous because
# 16 parallel fetches contend for bandwidth and large feeds (1MB+) were
# read-timing-out at a flat 10s, flapping healthy feeds into "error".
_FEED_TIMEOUT = (5, 25)

_session = None
_session_lock = threading.Lock()


def _get_session() -> requests.Session:
    """Shared session with retry adapters; thread-safe initialisation.

    The unguarded lazy init raced across the 16 fetch threads: a thread
    could grab the session after construction but before mount(), getting a
    session with NO retry adapter — its feeds silently lost their 429/5xx
    retries for that run.
    """
    global _session
    with _session_lock:
        if _session is None:
            session = requests.Session()
            session.headers.update(_FEED_HEADERS)
            retry = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET"],
            )
            adapter = HTTPAdapter(max_retries=retry)
            session.mount("https://", adapter)
            session.mount("http://", adapter)
            _session = session
    return _session


def _fetch_feed(url: str, region: str = "Global",
                user_agent: str | None = None) -> list[dict[str, Any]]:
    try:
        session = _get_session()
        # Per-feed UA override (config `user_agent:`) — some sites 403 the
        # default Chrome UA but accept others (e.g. Sekoia needs Firefox).
        headers = {"User-Agent": user_agent} if user_agent else None
        resp = session.get(url, timeout=_FEED_TIMEOUT, headers=headers)
        resp.raise_for_status()
        parsed = feedparser.parse(resp.content)

        # HTTP 200 with zero parseable entries and a parse error is NOT a
        # quiet feed — it's a bot-challenge page, WAF block, or moved feed.
        # Recording it as success made dead feeds look healthy ("ok, 0 new").
        if parsed.bozo and not parsed.entries:
            logger.error(
                f"Feed {url} returned HTTP {resp.status_code} but no parseable "
                f"entries (bozo: {getattr(parsed, 'bozo_exception', 'unknown')})"
            )
            record_fetch(url, success=False, entry_count=0)
            return []

        results = []
        for entry in parsed.entries:
            # Isolate per-entry failures: one malformed entry (missing title,
            # resolver blow-up) used to abort the whole feed and mark it as a
            # fetch error.
            try:
                title = getattr(entry, "title", "") or ""
                raw_link = getattr(entry, "link", "") or ""
                if not title:
                    logger.debug(f"Entry without title skipped in {url}")
                    continue
                # Drop articles whose primary link is a Tor/I2P address
                if not is_clearnet_url(raw_link):
                    logger.debug(f"Non-clearnet link skipped: {raw_link[:80]}")
                    continue
                raw_summary = entry.get("summary", "") or ""
                clean_link = resolve_original_url(raw_link, summary=raw_summary)
                # Resolved URL might have redirected to a .onion — guard again
                if not is_clearnet_url(clean_link):
                    clean_link = raw_link
                article_hash = hashlib.sha256(
                    (title + normalize_url(clean_link)).encode()
                ).hexdigest()
                results.append({
                    "title": title,
                    "link": clean_link,
                    "published": entry.get("published", ""),
                    "summary": entry.get("summary", ""),
                    "hash": article_hash,
                    "source": url,
                    "feed_region": region,
                })
            except Exception as entry_exc:
                logger.warning(f"Skipping malformed entry in {url}: {entry_exc}")
                continue

        cutoff = datetime.now(timezone.utc) - timedelta(days=FEED_CUTOFF_DAYS)
        filtered = []
        for r in results:
            pub = r.get("published", "")
            if pub:
                pub_dt = _parse_article_date(pub)
                if pub_dt is not None:
                    if pub_dt < cutoff:
                        continue
                else:
                    # No parseable date — skip article (prevents historic content leaking in)
                    logger.debug(f"Unparseable date, skipping: {r.get('title', '')[:60]}")
                    continue
            else:
                # No date at all — skip to prevent undated historic articles
                logger.debug(f"No date, skipping: {r.get('title', '')[:60]}")
                continue
            filtered.append(r)

        skipped = len(results) - len(filtered)
        logger.info(f"Fetched {len(filtered)} articles from {url} ({skipped} older than {FEED_CUTOFF_DAYS} days filtered)")
        record_fetch(url, success=True, entry_count=len(filtered))
        return filtered

    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        record_fetch(url, success=False, entry_count=0)
        return []


def fetch_articles(feeds_config: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from modules.config import MAX_FEED_FETCH_THREADS
    all_articles = []
    with ThreadPoolExecutor(max_workers=MAX_FEED_FETCH_THREADS) as executor:
        futures = {
            executor.submit(
                _fetch_feed,
                feed["url"],
                feed.get("region", "Global"),
                feed.get("user_agent"),
            ): feed["url"]
            for feed in feeds_config
        }
        for future in as_completed(futures):
            url = futures[future]
            try:
                articles = future.result()
                all_articles.extend(articles)
            except Exception as e:
                logger.error(f"Exception fetching {url}: {e}")

    logger.info(f"Total articles fetched: {len(all_articles)}")
    return all_articles
