import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
os.chdir(BASE_DIR)
sys.path.insert(0, str(BASE_DIR))

from modules.config import validate_config
from modules.feed_loader import load_feeds_from_files
from modules.feed_fetcher import fetch_articles
from modules.deduplicator import deduplicate_articles
from modules.language_tools import detect_language
from modules.article_scraper import process_urls_in_parallel
from modules.keyword_classifier import classify_article
from modules.logger_utils import setup_logger, log_article_summary
from modules.run_stats import RunStats
from modules.output_writer import (
    write_hourly_output,
    write_daily_output,
    write_rss_output,
)
from app.dashboard import build_dashboard
from modules.cost_tracker import get_today_spend, get_total_spend
from modules.darkweb_monitor import fetch_darkweb_intel


def enrich_articles(articles, summarize=False, stats=None):
    url_list = [a["link"] for a in articles]
    url_to_content = process_urls_in_parallel(url_list)

    if stats:
        stats.scrape_successes = sum(1 for v in url_to_content.values() if v)
        stats.scrape_failures = sum(1 for v in url_to_content.values() if not v)

    enriched = []
    for article in articles:
        original_url = article["link"]
        full_content = url_to_content.get(original_url)

        lang = detect_language(article["title"])

        result = classify_article(
            title=article["title"],
            content=full_content if summarize else None,
            source_language=lang,
        )

        if stats:
            if result.get("_cached"):
                stats.cache_hits += 1
            else:
                stats.cache_misses += 1

        enriched_article = {
            **article,
            "translated_title": result.get("translated_title", article["title"]),
            "language": lang,
            "is_cyber_attack": result.get("is_cyber_attack", False),
            "category": result.get("category", "Unknown"),
            "confidence": result.get("confidence", 0),
            "full_content": full_content,
            "summary": result.get("summary", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if enriched_article["is_cyber_attack"]:
            if summarize and enriched_article["summary"]:
                log_article_summary(original_url, enriched_article["summary"])
            enriched.append(enriched_article)
            if stats:
                stats.cyber_articles += 1
        else:
            if stats:
                stats.non_cyber_articles += 1

    return enriched


def main():
    setup_logger()
    validate_config()
    logging.info("==== Starting ThreatDigest Main Run ====")

    stats = RunStats()

    feed_paths = [
        str(BASE_DIR / "config" / "feeds_bing.yaml"),
        str(BASE_DIR / "config" / "feeds_google.yaml"),
        str(BASE_DIR / "config" / "feeds_native.yaml"),
    ]
    all_feeds = load_feeds_from_files(feed_paths)
    stats.feeds_loaded = len(all_feeds)
    if not all_feeds:
        logging.warning("No feeds found. Exiting.")
        stats.finalize()
        return

    raw_articles = fetch_articles(all_feeds)

    # Dark web monitoring (zero cost — clearnet aggregators)
    try:
        darkweb_articles = fetch_darkweb_intel()
        if darkweb_articles:
            raw_articles.extend(darkweb_articles)
            logging.info(f"Dark web: added {len(darkweb_articles)} items")
    except Exception as e:
        logging.warning(f"Dark web monitoring failed: {e}")

    stats.articles_fetched = len(raw_articles)
    if not raw_articles:
        logging.warning("No articles fetched.")
        stats.finalize()
        return

    unique_articles = deduplicate_articles(raw_articles)
    stats.articles_after_dedup = len(unique_articles)
    stats.news_reviewed = len(raw_articles)
    if not unique_articles:
        logging.info("No new articles after deduplication.")
        stats.finalize()
        return

    enriched_articles = enrich_articles(unique_articles, summarize=True, stats=stats)
    stats.articles_enriched = len(enriched_articles)
    if not enriched_articles:
        logging.info("No cyberattack-related articles after enrichment.")
        stats.finalize()
        return

    write_hourly_output(enriched_articles)
    write_daily_output(enriched_articles)
    write_rss_output(enriched_articles)

    stats.finalize()

    try:
        build_dashboard()
    except Exception as e:
        logging.warning(f"Dashboard generation failed: {e}")

    logging.info(
        f"==== ThreatDigest Run Complete - {len(enriched_articles)} articles | "
        f"API cost today: ${get_today_spend():.4f} | "
        f"Total spend: ${get_total_spend():.4f} ===="
    )


if __name__ == "__main__":
    main()
