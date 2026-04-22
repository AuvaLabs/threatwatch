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
from typing import Any

logger = logging.getLogger(__name__)


def run_ai_enrichment(
    all_articles: list[dict[str, Any]],
    new_batch: list[dict[str, Any]] | None = None,
) -> None:
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
    try:
        generate_briefing(all_articles)
    except Exception as e:
        logger.warning(f"Global briefing failed: {e}")

    # Tier 1b: Regional digests — NA, EMEA, APAC
    try:
        generate_regional_briefings(all_articles)
    except Exception as e:
        logger.warning(f"Regional digests failed: {e}")

    # Tier 2: Top stories
    try:
        generate_top_stories(all_articles)
    except Exception as e:
        logger.warning(f"Top stories failed: {e}")

    # Tier 3: Per-article summaries on new batch only
    try:
        summarize_articles(new_batch)
    except Exception as e:
        logger.warning(f"Article summaries failed: {e}")
