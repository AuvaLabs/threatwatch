#!/usr/bin/env python3
"""One-shot: run the AI summariser over the full persisted corpus.

The normal pipeline only invokes `summarize_articles` on the current
enrichment batch (the new articles ingested this cycle). Articles that were
already in `daily_latest.json` at an earlier time and never had a summary
are therefore never revisited — 50%+ of the corpus sat without a summary
despite the per-run cap being generous enough.

This script runs the same summariser over the whole file, writes in place,
and rotates through batches of MAX_SUMMARIES_PER_RUN until every eligible
article has a summary or the LLM budget is exhausted. Safe to re-run.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.config import OUTPUT_DIR
from modules.article_summariser import summarize_articles

logging.basicConfig(level=logging.INFO, format="%(asctime)s [backfill] %(message)s")

DAILY_PATH = OUTPUT_DIR / "daily_latest.json"


def main() -> int:
    if not DAILY_PATH.exists():
        logging.error("daily_latest.json not found at %s", DAILY_PATH)
        return 1
    with open(DAILY_PATH, encoding="utf-8") as f:
        articles = json.load(f)

    def eligible():
        return [
            a for a in articles
            if a.get("is_cyber_attack") and a.get("title")
            and not (a.get("summary") or "").strip()
        ]

    pending = eligible()
    total_pending = len(pending)
    logging.info("starting: %d/%d articles need a summary", total_pending, len(articles))

    generated = 0
    passes = 0
    while True:
        pending = eligible()
        if not pending:
            break
        # summarize_articles writes back into the dicts we pass by reference,
        # which are the same dicts inside `articles`. Each pass processes
        # MAX_SUMMARIES_PER_RUN articles at most.
        this_pass = summarize_articles(articles)
        if this_pass == 0:
            # LLM unavailable / rate-limited / out of budget — stop cleanly.
            logging.info("summariser returned 0 this pass, stopping")
            break
        generated += this_pass
        passes += 1
        logging.info("pass %d: %d new summaries, %d still pending",
                     passes, this_pass, len(eligible()))

    with open(DAILY_PATH, "w", encoding="utf-8") as f:
        json.dump(articles, f, ensure_ascii=False)
    logging.info("done: %d summaries generated in %d passes, %d still unsummarised",
                 generated, passes, len(eligible()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
