#!/usr/bin/env python3
"""Out-of-band AI enrichment runner.

Loads the current article corpus from disk and runs briefing / regional /
top-stories / summaries on it. Designed to be invoked by the scheduler on
its own cadence (every 30-60 min), independent of the main pipeline's
10-min fetch loop, so Groq rate limits don't block feed ingestion.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
os.chdir(BASE_DIR)
sys.path.insert(0, str(BASE_DIR))

from modules.logger_utils import setup_logger  # noqa: E402


def main() -> None:
    setup_logger()
    logging.info("==== Starting AI enrichment run ====")

    # SSRF guard parity with the main pipeline.
    try:
        from modules.safe_http import install_ssrf_guard
        install_ssrf_guard()
    except Exception as e:
        logging.warning(f"SSRF guard install failed: {e}")

    from modules.output_writer import load_existing, STATIC_DAILY
    all_articles = load_existing(STATIC_DAILY)
    if not all_articles:
        logging.warning("No articles on disk — skipping AI enrichment.")
        return

    from modules.ai_enrichment import run_ai_enrichment
    run_ai_enrichment(all_articles)

    logging.info("==== AI enrichment run complete ====")


if __name__ == "__main__":
    main()
