import feedparser
import hashlib
import logging
import requests
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import parsedate_to_datetime

from modules.config import FEED_CUTOFF_DAYS
from modules.url_resolver import resolve_original_url

_FEED_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
}

_FEED_TIMEOUT = 10  # seconds

_session = None


def _get_session():
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update(_FEED_HEADERS)
    return _session


def _fetch_feed(url, region="Global"):
    try:
        session = _get_session()
        resp = session.get(url, timeout=_FEED_TIMEOUT)
        resp.raise_for_status()
        parsed = feedparser.parse(resp.content)
        results = []

        for entry in parsed.entries:
            clean_link = resolve_original_url(entry.link)
            article_hash = hashlib.sha256(
                (entry.title + clean_link).encode()
            ).hexdigest()
            results.append({
                "title": entry.title,
                "link": clean_link,
                "published": entry.get("published", ""),
                "summary": entry.get("summary", ""),
                "hash": article_hash,
                "source": url,
                "feed_region": region,
            })

        cutoff = datetime.now() - timedelta(days=FEED_CUTOFF_DAYS)
        filtered = []
        for r in results:
            pub = r.get("published", "")
            if pub:
                try:
                    pub_dt = parsedate_to_datetime(pub)
                    if pub_dt.replace(tzinfo=None) < cutoff:
                        continue
                except (ValueError, TypeError):
                    pass
            filtered.append(r)

        skipped = len(results) - len(filtered)
        logging.info(f"Fetched {len(filtered)} articles from {url} ({skipped} older than {FEED_CUTOFF_DAYS} days filtered)")
        return filtered

    except Exception as e:
        logging.error(f"Error fetching {url}: {e}")
        return []


def fetch_articles(feeds_config):
    all_articles = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(_fetch_feed, feed["url"], feed.get("region", "Global")): feed["url"]
            for feed in feeds_config
        }
        for future in as_completed(futures):
            url = futures[future]
            try:
                articles = future.result()
                all_articles.extend(articles)
            except Exception as e:
                logging.error(f"Exception fetching {url}: {e}")

    logging.info(f"Total articles fetched: {len(all_articles)}")
    return all_articles
