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
from modules.hybrid_classifier import classify_article
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
from modules.feed_health import log_health_summary
from modules.webhook import dispatch as webhook_dispatch
from modules.watchlist_monitor import tag_articles_with_vendors, run_watchlist_monitor
from modules.newsapi_fetcher import fetch_newsapi_articles
from modules.region_inferrer import infer_articles_regions
from modules.nvd_fetcher import fetch_nvd_cves
from modules.epss_enricher import enrich_articles_with_epss
from modules.attack_tagger import tag_articles_with_attack
from modules.trend_detector import update_trends


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

        # Skip classification for pre-classified articles (e.g., NVD CVEs)
        pre_classified = article.get("is_cyber_attack") is not None and article.get("confidence", 0) > 0
        if pre_classified:
            result = {
                "is_cyber_attack": article["is_cyber_attack"],
                "category": article.get("category", "General Cyber Threat"),
                "confidence": article.get("confidence", 0),
                "translated_title": article.get("translated_title", article["title"]),
                "summary": article.get("summary", ""),
            }
        else:
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
            if result.get("_ai_enhanced"):
                stats.ai_escalations = getattr(stats, "ai_escalations", 0) + 1

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
    log_health_summary()

    # Dark web monitoring (zero cost — clearnet aggregators)
    try:
        darkweb_articles = fetch_darkweb_intel()
        if darkweb_articles:
            raw_articles.extend(darkweb_articles)
            logging.info(f"Dark web: added {len(darkweb_articles)} items")
    except Exception as e:
        logging.warning(f"Dark web monitoring failed: {e}")

    # NewsAPI — structured security news (rate-limited: at most once per 30 min)
    try:
        newsapi_articles = fetch_newsapi_articles()
        if newsapi_articles:
            raw_articles.extend(newsapi_articles)
            logging.info(f"NewsAPI: added {len(newsapi_articles)} articles")
    except Exception as e:
        logging.warning(f"NewsAPI fetch failed: {e}")

    # NVD CVE monitoring (zero cost — public API)
    try:
        nvd_articles = fetch_nvd_cves()
        if nvd_articles:
            raw_articles.extend(nvd_articles)
            logging.info(f"NVD: added {len(nvd_articles)} high/critical CVEs")
    except Exception as e:
        logging.warning(f"NVD CVE fetch failed: {e}")

    # Watchlist monitor — custom brand/asset keywords (self-hosted only)
    try:
        watchlist_articles = run_watchlist_monitor()
        if watchlist_articles:
            raw_articles.extend(watchlist_articles)
            logging.info(f"Watchlist: added {len(watchlist_articles)} custom keyword articles")
    except Exception as e:
        logging.warning(f"Watchlist monitor failed: {e}")

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
    # Tag every article with matching suggest-list vendors (fast regex pass)
    enriched_articles = tag_articles_with_vendors(enriched_articles)
    # Refine region assignments using content-based inference
    enriched_articles = infer_articles_regions(enriched_articles)

    # EPSS exploit prediction scores for CVE-containing articles
    try:
        enriched_articles = enrich_articles_with_epss(enriched_articles)
    except Exception as e:
        logging.warning(f"EPSS enrichment failed: {e}")

    # MITRE ATT&CK technique tagging
    try:
        enriched_articles = tag_articles_with_attack(enriched_articles)
    except Exception as e:
        logging.warning(f"ATT&CK tagging failed: {e}")

    # Trend detection — update keyword/category frequency tracking
    try:
        update_trends(enriched_articles)
    except Exception as e:
        logging.warning(f"Trend detection failed: {e}")

    stats.articles_enriched = len(enriched_articles)
    if not enriched_articles:
        logging.info("No cyberattack-related articles after enrichment.")
        stats.finalize()
        return

    write_hourly_output(enriched_articles)
    write_daily_output(enriched_articles)
    write_rss_output(enriched_articles)

    # Webhook alerts (optional — only runs if WEBHOOK_URL is configured)
    try:
        webhook_dispatch(enriched_articles)
    except Exception as e:
        logging.debug(f"Webhook dispatch skipped: {e}")

    # Load full corpus for AI features (not just new batch)
    from modules.output_writer import _load_existing, STATIC_DAILY
    all_articles = _load_existing(STATIC_DAILY)
    if not all_articles:
        all_articles = enriched_articles

    # AI enrichment (optional — only runs if LLM API key is set)
    try:
        from modules.briefing_generator import (
            generate_briefing, generate_top_stories, summarize_articles,
            generate_regional_briefings,
        )
        # Tier 1: Global intelligence digest (1x/hour, ~7K tokens)
        generate_briefing(all_articles)
        # Tier 1b: Regional digests — NA, EMEA, APAC (1x/hour each, ~4K tokens each)
        generate_regional_briefings(all_articles)
        # Tier 2: Top stories (1x/hour, ~5K tokens)
        generate_top_stories(all_articles)
        # Tier 3: Article summaries on new batch only (up to 30/run)
        summarize_articles(enriched_articles)
    except Exception as e:
        logging.warning(f"AI enrichment skipped: {e}")

    # Incident clustering + actor profiles on FULL corpus
    try:
        if all_articles:
            from modules.incident_correlator import cluster_articles
            cluster_articles(all_articles)

            from modules.actor_profiler import generate_profiles
            generate_profiles(all_articles)
    except Exception as e:
        logging.warning(f"Clustering/profiling failed: {e}")

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
