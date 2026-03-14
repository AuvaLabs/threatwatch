import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from modules.config import OUTPUT_DIR
from modules.cost_tracker import get_today_spend, get_total_spend

STATS_FILE = OUTPUT_DIR / "stats.json"


def _load_stats():
    if STATS_FILE.exists():
        try:
            with open(STATS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"runs": []}
    return {"runs": []}


def _save_stats(data):
    STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


class RunStats:
    def __init__(self):
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.feeds_loaded = 0
        self.articles_fetched = 0
        self.news_reviewed = 0
        self.articles_after_dedup = 0
        self.articles_enriched = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.scrape_successes = 0
        self.scrape_failures = 0
        self.cyber_articles = 0
        self.non_cyber_articles = 0
        self.analysis_failures = 0
        self.budget_exceeded = False

    def finalize(self):
        stats = _load_stats()

        try:
            from modules.ai_engine import get_failure_stats
            failure_stats = get_failure_stats()
            self.budget_exceeded = failure_stats.get("budget_skips", 0) > 0
        except Exception:
            pass

        if self.budget_exceeded:
            logging.warning(
                "AI budget was exceeded this run — some articles used keyword classification only."
            )

        run = {
            "started_at": self.started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "feeds_loaded": self.feeds_loaded,
            "articles_fetched": self.articles_fetched,
            "news_reviewed": self.news_reviewed,
            "articles_after_dedup": self.articles_after_dedup,
            "articles_enriched": self.articles_enriched,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "scrape_successes": self.scrape_successes,
            "scrape_failures": self.scrape_failures,
            "cyber_articles": self.cyber_articles,
            "non_cyber_articles": self.non_cyber_articles,
            "analysis_failures": self.analysis_failures,
            "budget_exceeded": self.budget_exceeded,
            "api_cost_today": round(get_today_spend(), 4),
            "api_cost_total": round(get_total_spend(), 4),
        }

        stats["runs"].append(run)
        stats["runs"] = stats["runs"][-100:]
        stats["latest"] = run
        _save_stats(stats)

        logging.info(
            f"Run stats: {self.articles_fetched} fetched, "
            f"{self.news_reviewed} news reviewed, "
            f"{self.cyber_articles} cyber articles, "
            f"{self.cache_hits} cache hits, "
            f"{self.scrape_successes}/{self.articles_after_dedup} scraped"
        )
