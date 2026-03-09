import json
import logging
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

from feedgen.feed import FeedGenerator

from modules.config import SITE_URL, SITE_DOMAIN, OUTPUT_DIR, FEED_CUTOFF_DAYS

HOURLY_DIR = OUTPUT_DIR / "hourly"
DAILY_DIR = OUTPUT_DIR / "daily"
RSS_PATH = OUTPUT_DIR / "rss_cyberattacks.xml"
STATIC_HOURLY = OUTPUT_DIR / "hourly_latest.json"
STATIC_DAILY = OUTPUT_DIR / "daily_latest.json"


def _ensure_dir(path):
    path.mkdir(parents=True, exist_ok=True)


def _write_json(data, path):
    _ensure_dir(path.parent)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    logging.info(f"Saved JSON to {path} ({len(data)} articles)")


def _load_existing(path):
    """Load existing articles from JSON file."""
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError):
        return []


def _merge_articles(existing, new_articles):
    """Merge new articles into existing, dedup by hash, drop older than cutoff."""
    seen_hashes = set()
    merged = []

    # New articles take priority (added first)
    for article in new_articles:
        h = article.get("hash", "")
        if h and h not in seen_hashes:
            seen_hashes.add(h)
            merged.append(article)

    # Then add existing articles not already in new batch
    for article in existing:
        h = article.get("hash", "")
        if h and h not in seen_hashes:
            seen_hashes.add(h)
            merged.append(article)

    # Drop articles older than cutoff window
    cutoff = datetime.now(timezone.utc) - timedelta(days=FEED_CUTOFF_DAYS)
    filtered = []
    for article in merged:
        ts = article.get("timestamp", "")
        if ts:
            try:
                article_dt = datetime.fromisoformat(ts)
                if article_dt.replace(tzinfo=timezone.utc) < cutoff:
                    continue
            except (ValueError, TypeError):
                pass
        filtered.append(article)

    # Sort by timestamp descending (newest first)
    filtered.sort(
        key=lambda a: a.get("timestamp", "1970-01-01"),
        reverse=True,
    )

    logging.info(
        f"Merged: {len(new_articles)} new + {len(existing)} existing "
        f"= {len(filtered)} total (after dedup + cutoff)"
    )
    return filtered


def write_hourly_output(articles):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H")
    _write_json(articles, HOURLY_DIR / f"{timestamp}.json")
    # Merge into rolling hourly latest
    existing = _load_existing(STATIC_HOURLY)
    merged = _merge_articles(existing, articles)
    _write_json(merged, STATIC_HOURLY)


def write_daily_output(articles):
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    _write_json(articles, DAILY_DIR / f"{date}.json")
    # Merge into rolling daily latest (keeps all articles within cutoff window)
    existing = _load_existing(STATIC_DAILY)
    merged = _merge_articles(existing, articles)
    _write_json(merged, STATIC_DAILY)


def _parse_pub_date(date_str):
    from email.utils import parsedate_to_datetime

    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        pass
    try:
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    # Try common formats without timezone
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return datetime.now(timezone.utc)


def write_rss_output(articles):
    fg = FeedGenerator()
    fg.id(f"{SITE_URL}/threatdigest")
    fg.title("ThreatDigest Hub - Curated Cyber Incidents")
    fg.link(href=SITE_URL, rel="self")
    fg.language("en")
    fg.description(
        "A curated list of recent cyber incidents, attacks, and security threats."
    )

    for article in articles:
        fe = fg.add_entry()
        fe.title(article.get("title", "No Title"))
        fe.link(href=article.get("link", "#"))

        summary_text = article.get("summary", "")
        if not summary_text:
            summary_text = article.get("summary", "No summary available.")
        fe.description(summary_text)

        pub_date = _parse_pub_date(
            article.get("published", datetime.now(timezone.utc).isoformat())
        )
        fe.pubDate(pub_date)

    _ensure_dir(RSS_PATH.parent)
    fg.rss_file(str(RSS_PATH))
    logging.info(f"RSS feed saved to {RSS_PATH}")
