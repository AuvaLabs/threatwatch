import json
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)
from email.utils import format_datetime
from pathlib import Path

from feedgen.feed import FeedGenerator

from modules.config import SITE_URL, SITE_DOMAIN, OUTPUT_DIR, FEED_CUTOFF_DAYS
from modules.date_utils import parse_datetime
from modules.regions import collapse_regions as _collapse_regions
from modules.regions import MAX_MERGED_REGIONS as _MAX_MERGED_REGIONS

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
    logger.info(f"Saved JSON to {path} ({len(data)} articles)")


def load_existing(path):
    """Load existing articles from a persisted JSON list file.

    Public replacement for the legacy underscore-prefixed name. Returns an
    empty list when the file is missing, malformed, or not a JSON array.
    """
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError):
        return []


# Legacy alias retained so existing callers (tests, external scripts) that
# imported the underscore-prefixed name continue to work.
_load_existing = load_existing


def _merge_articles(existing, new_articles):
    """Merge new articles into existing, dedup by hash AND title, drop older than cutoff."""
    seen_hashes = set()
    seen_titles = set()
    merged = []

    def _add(article):
        # Every article written by the pipeline must have a hash assigned by
        # deduplicate_articles. Anything reaching this merge step without one
        # is malformed data (bypassed dedup, legacy load, corrupt JSON) and
        # gets dropped instead of mixed into the persisted corpus.
        h = article.get("hash", "")
        if not h:
            return
        title = article.get("title", "").strip().lower()
        if h in seen_hashes:
            return
        if title and title in seen_titles:
            return
        seen_hashes.add(h)
        if title:
            seen_titles.add(title)
        merged.append(article)

    # New articles take priority (added first)
    for article in new_articles:
        _add(article)

    # Then add existing articles not already in new batch
    for article in existing:
        _add(article)

    # Drop articles older than cutoff window. Policy: judge each article by
    # its OWN publication date when parseable; fall back to ingestion time
    # (ingested_at / legacy timestamp) when `published` is corrupt or absent.
    # The old "drop if EITHER date is old" policy silently discarded fresh
    # articles whose upstream feed shipped a corrupt `published`; judging by
    # the best available single date keeps them for a full window from
    # ingestion instead. Articles with NO parseable date at all are kept —
    # dropping undatable data would silently bleed legit articles.
    cutoff = datetime.now(timezone.utc) - timedelta(days=FEED_CUTOFF_DAYS)
    filtered = []
    for article in merged:
        article_dt = (
            parse_datetime(article.get("published", ""))
            or parse_datetime(article.get("ingested_at", ""))
            or parse_datetime(article.get("timestamp", ""))
        )
        if article_dt is not None and article_dt < cutoff:
            continue
        filtered.append(article)

    # Re-collapse stale multi-region strings from old data
    for article in filtered:
        region = article.get("feed_region", "")
        if "," in region:
            parts = set(region.split(","))
            article["feed_region"] = _collapse_regions(parts)

    # Sort by publication date descending (newest first). Sorting by the
    # ingestion timestamp made every old article re-enriched today float to
    # the top of the corpus as if it were breaking news; consumers of this
    # file (API, integrations) must see real event order. Ingestion time is
    # only a tie-break fallback for articles with no parseable published.
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    filtered.sort(
        key=lambda a: (
            parse_datetime(a.get("published", ""))
            or parse_datetime(a.get("ingested_at", ""))
            or parse_datetime(a.get("timestamp", ""))
            or epoch
        ),
        reverse=True,
    )

    logger.info(
        f"Merged: {len(new_articles)} new + {len(existing)} existing "
        f"= {len(filtered)} total (after dedup + cutoff)"
    )
    return filtered


def write_hourly_output(articles):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H")
    _write_json(articles, HOURLY_DIR / f"{timestamp}.json")
    # Merge into rolling hourly latest
    existing = load_existing(STATIC_HOURLY)
    merged = _merge_articles(existing, articles)
    _write_json(merged, STATIC_HOURLY)


def write_daily_output(articles):
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    _write_json(articles, DAILY_DIR / f"{date}.json")
    # SQLite write (Phase 3): upsert batch and prune to the same cutoff window
    # used by the JSON merge. Server reads from SQLite (READ_FROM_SQLITE=1);
    # JSON files below remain as backup and for the parity-check fallback.
    try:
        from modules.db import upsert_articles, prune_older_than
        n = upsert_articles(articles)
        cutoff_iso = (datetime.now(timezone.utc) - timedelta(days=FEED_CUTOFF_DAYS)).isoformat()
        pruned = prune_older_than(cutoff_iso)
        logger.debug(f"SQLite: {n} articles upserted, {pruned} pruned (cutoff={FEED_CUTOFF_DAYS}d)")
    except Exception as exc:
        logger.warning(f"SQLite write skipped: {exc}")
    # Merge into rolling daily latest (keeps all articles within cutoff window)
    existing = load_existing(STATIC_DAILY)
    merged = _merge_articles(existing, articles)
    _write_json(merged, STATIC_DAILY)


def _parse_pub_date(date_str):
    """Back-compat shim — returns `datetime.now()` on failure as older callers
    expected. New code should call `parse_datetime` directly and handle None.
    """
    return parse_datetime(date_str) or datetime.now(timezone.utc)


def write_rss_output(articles):
    fg = FeedGenerator()
    fg.id(f"{SITE_URL}/threatdigest")
    fg.title("ThreatWatch - Curated Cyber Threat Intelligence")
    fg.link(href=SITE_URL, rel="alternate")
    fg.link(href=f"{SITE_URL}/api/rss", rel="self")
    fg.language("en")
    fg.description(
        "A curated list of recent cyber incidents, attacks, and security threats."
    )

    for article in articles:
        fe = fg.add_entry()
        fe.title(article.get("title", "No Title"))
        link = article.get("link", "#")
        fe.link(href=link)

        # Use link as guid (permalink) for reliable deduplication by RSS readers
        fe.guid(link, permalink=True)

        # Add category if present
        category = article.get("category")
        if category:
            fe.category(term=category)

        summary_text = article.get("summary") or "No summary available."
        fe.description(summary_text)

        # RSS items REQUIRE a pubDate (feedgen validates). If we can't parse
        # the upstream date, fall back to the article's INGESTION time — a
        # real, stable moment we observed — never render-time now(), which
        # re-stamped stale corrupt-date items as breaking news on every
        # regeneration of the feed.
        pub_date = (
            parse_datetime(article.get("published", ""))
            or parse_datetime(article.get("ingested_at", ""))
            or parse_datetime(article.get("timestamp", ""))
            or datetime.now(timezone.utc)
        )
        fe.pubDate(pub_date)

    _ensure_dir(RSS_PATH.parent)
    fg.rss_file(str(RSS_PATH))
    logger.info(f"RSS feed saved to {RSS_PATH}")
