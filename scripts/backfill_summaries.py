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
import os
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.config import OUTPUT_DIR
from modules.llm_client import reset_circuit
from modules.output_writer import persist_corpus
# Import via briefing_generator so its load order resolves the re-export
# cycle that otherwise bites when article_summariser is loaded first.
from modules.briefing_generator import summarize_articles

logging.basicConfig(level=logging.INFO, format="%(asctime)s [backfill] %(message)s")

DAILY_PATH = OUTPUT_DIR / "daily_latest.json"
# Seconds between passes so provider request and token windows can clear.
# Individual uncached batches are paced by SUMMARY_BATCH_DELAY_SECONDS.
SLEEP_BETWEEN_PASSES = float(os.environ.get("BACKFILL_SUMMARY_SLEEP", "10"))


def _load() -> list[dict]:
    with open(DAILY_PATH, encoding="utf-8") as f:
        return json.load(f)


def _save_with_merge(summaries_by_hash: dict[str, dict]) -> int:
    """Re-read daily_latest, apply our per-hash summaries, write back.

    Re-reading under a lock-free scheme is still racy, but the window shrinks
    to milliseconds and the merge-by-hash ensures pipeline-written articles
    (new hashes the backfill never touched) survive. Returns the number of
    articles the merge actually modified.
    """
    fresh = _load()
    touched = 0
    for a in fresh:
        h = a.get("hash")
        if not h or h not in summaries_by_hash:
            continue
        s = summaries_by_hash[h]
        # Don't clobber a summary the pipeline or analyst added in the meantime.
        if (a.get("summary") or "").strip():
            continue
        a["summary"] = s["summary"]
        a["summary_method"] = s.get("summary_method") or "ai"
        a["summary_generated"] = s.get("summary_generated", True)
        for k in ("intel_what", "intel_who", "intel_impact"):
            if s.get(k):
                a[k] = s[k]
        touched += 1
    persist_corpus(fresh)
    return touched


def main() -> int:
    if not DAILY_PATH.exists():
        logging.error("daily_latest.json not found at %s", DAILY_PATH)
        return 1

    def eligible(articles):
        return [
            a for a in articles
            if a.get("is_cyber_attack") and a.get("title")
            and not (a.get("summary") or "").strip()
        ]

    articles = _load()
    total_pending = len(eligible(articles))
    logging.info("starting: %d/%d articles need a summary", total_pending, len(articles))

    total_touched = 0
    passes = 0
    while True:
        pending = eligible(articles)
        if not pending:
            break
        # Each pass starts fresh — clear the circuit so a streak of 429s
        # earlier in the run can't poison subsequent passes.
        reset_circuit()
        # summarize_articles mutates the dicts we pass. We work over our own
        # loaded copy here, so that mutation is scoped to in-memory dicts;
        # the disk write happens via _save_with_merge which re-reads and
        # merges by hash so we don't clobber concurrent pipeline writes.
        this_pass = summarize_articles(articles)
        if this_pass == 0:
            # Pace and retry once before quitting — a transient 429 streak
            # shouldn't cap the run early.
            logging.info("pass returned 0; sleeping %.0fs then retrying once",
                         SLEEP_BETWEEN_PASSES * 3)
            time.sleep(SLEEP_BETWEEN_PASSES * 3)
            reset_circuit()
            this_pass = summarize_articles(articles)
            if this_pass == 0:
                logging.info("summariser still returned 0, stopping")
                break
        # Collect what we just wrote so the merge step on disk can apply it.
        summaries_by_hash: dict[str, dict] = {}
        for a in articles:
            h = a.get("hash")
            if h and (a.get("summary") or "").strip():
                summaries_by_hash[h] = {
                    "summary": a.get("summary"),
                    "intel_what": a.get("intel_what"),
                    "intel_who": a.get("intel_who"),
                    "intel_impact": a.get("intel_impact"),
                    "summary_method": a.get("summary_method"),
                    "summary_generated": a.get("summary_generated"),
                }
        touched = _save_with_merge(summaries_by_hash)
        # Reload so subsequent passes see the latest pipeline additions too.
        articles = _load()
        total_touched += touched
        passes += 1
        remaining = len(eligible(articles))
        logging.info("pass %d: %d summaries merged, %d still pending",
                     passes, touched, remaining)
        if remaining > 0:
            time.sleep(SLEEP_BETWEEN_PASSES)

    logging.info("done: %d summaries merged in %d passes, %d still unsummarised",
                 total_touched, passes, len(eligible(articles)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
