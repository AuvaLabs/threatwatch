"""AI enrichment orchestrator.

Extracted from ``threatdigest_main.py`` so the AI features (briefing,
regional digests, top stories, article summaries) can run either inline
with the main pipeline OR on a separate cadence via
``scripts/run_ai_enrichment.py``. Decoupling them means Groq rate limits
and load-shed events don't block feed fetching on every 10-min pipeline
tick.

The behaviour is identical either way — this module just gives both
entry points a single shared implementation.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from modules.config import STATE_DIR
from modules.utils import write_json_atomic

logger = logging.getLogger(__name__)


def run_ai_enrichment(
    all_articles: list[dict[str, Any]],
    new_batch: list[dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Run the four AI tiers in order, short-circuiting on circuit-breaker trip.

    Args:
        all_articles: Full corpus for briefing / regional / top stories.
        new_batch: The new batch for article summaries. Defaults to
            ``all_articles`` when the caller is running out-of-band.

    Never raises — every tier is individually guarded. The circuit breaker
    inside ``llm_client`` trips after N consecutive failures so a single
    Groq outage cannot cascade across all four tiers.
    """
    if new_batch is None:
        new_batch = all_articles
    pending_summaries = sum(
        1 for article in new_batch
        if article.get("is_cyber_attack") and not article.get("summary")
    )

    # Reset breaker at the start of each enrichment invocation — the process
    # may be long-lived (inline pipeline) or short-lived (out-of-band cron).
    try:
        from modules.llm_client import reset_circuit
        reset_circuit()
    except Exception:
        pass

    from modules.briefing_generator import (
        generate_briefing, generate_top_stories, summarize_articles,
        generate_regional_briefings,
    )

    # Tier 1: Global intelligence digest (rate-limited to ~1x/hour by module)
    results: dict[str, dict[str, Any]] = {}
    briefing = None
    try:
        briefing = generate_briefing(all_articles)
        results["global_briefing"] = {"ok": bool(briefing)}
    except Exception as e:
        logger.warning(f"Global briefing failed: {e}")
        results["global_briefing"] = {"ok": False, "error": "generation_failed"}

    # Fire a webhook alert if the briefing's threat_level clears the configured
    # minimum. Deduplicated by modules/webhook._should_alert_briefing so the
    # same level doesn't re-alert every run. Guarded — alert failures must
    # never abort the rest of enrichment.
    try:
        from modules.webhook import dispatch_briefing_alert
        dispatch_briefing_alert(briefing)
    except Exception as e:
        logger.warning(f"Briefing alert dispatch failed: {e}")

    # Independent Telegram channel post — same level/cooldown logic but its own
    # state file so an org can drive Slack and Telegram in parallel without
    # one path muting the other. Broad catch is intentional (alert failures
    # must not abort enrichment); exc_info preserves the traceback so a
    # programmer-error (TypeError/AttributeError) is still diagnosable in logs.
    try:
        from modules.telegram import dispatch_telegram_briefing
        dispatch_telegram_briefing(briefing)
    except Exception:
        logger.warning("Telegram briefing dispatch failed", exc_info=True)

    # Tier 1b: Regional digests — NA, EMEA, APAC
    try:
        regional = generate_regional_briefings(all_articles) or {}
        missing_regions = sorted({"na", "emea", "apac"} - set(regional))
        results["regional_briefings"] = {
            "ok": not missing_regions,
            "missing": missing_regions,
        }
    except Exception as e:
        logger.warning(f"Regional digests failed: {e}")
        results["regional_briefings"] = {"ok": False, "error": "generation_failed"}

    # Tier 2: Top stories
    try:
        top_stories = generate_top_stories(all_articles)
        results["top_stories"] = {"ok": bool(top_stories)}
    except Exception as e:
        logger.warning(f"Top stories failed: {e}")
        results["top_stories"] = {"ok": False, "error": "generation_failed"}

    # Tier 3: Per-article summaries on new batch only
    try:
        raw_summary_count = summarize_articles(new_batch)
        summary_count = raw_summary_count if isinstance(raw_summary_count, int) else 0
        summary_ok = pending_summaries == 0 or summary_count > 0
        results["article_summaries"] = {
            "ok": summary_ok,
            "count": summary_count,
            "pending": pending_summaries,
        }
    except Exception as e:
        logger.warning(f"Article summaries failed: {e}")
        results["article_summaries"] = {"ok": False, "error": "generation_failed", "count": 0}

    status = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "capabilities": results,
    }
    try:
        write_json_atomic(STATE_DIR / "ai_health.json", status, ensure_ascii=False)
    except OSError as exc:
        logger.warning("AI health status write failed: %s", exc)
    return results
