#!/usr/bin/env python3
"""One-shot importer: seed SQLite from the current JSON persisted state.

Run after deploying the SQLite schema but before the next pipeline cycle so
`modules/db.py` has a populated store from day one. Idempotent: re-running
upserts each row, so the script is safe to re-run after partial failure.

Usage (inside the pipeline container):
    python3 scripts/import_to_sqlite.py
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.config import OUTPUT_DIR
from modules.db import upsert_articles, upsert_campaign, stats

logging.basicConfig(level=logging.INFO, format="%(asctime)s [import] %(message)s")


def _load_json(path: Path, kind: str) -> list | dict | None:
    if not path.exists():
        logging.warning(f"{kind} source missing: {path}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logging.error(f"{kind} parse failed at {path}: {exc}")
        return None


def main() -> int:
    daily = _load_json(OUTPUT_DIR / "daily_latest.json", "articles")
    if isinstance(daily, list) and daily:
        n = upsert_articles(daily)
        logging.info(f"Upserted {n} articles from daily_latest.json")

    camps = _load_json(OUTPUT_DIR / "campaigns.json", "campaigns")
    if isinstance(camps, dict):
        for c in camps.values():
            upsert_campaign(c)
        logging.info(f"Upserted {len(camps)} campaigns")

    s = stats()
    logging.info(
        "SQLite now holds %d articles and %d campaigns (%.1f KB on disk: %s)",
        s["article_count"], s["campaign_count"], s["db_bytes"] / 1024, s["db_path"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
