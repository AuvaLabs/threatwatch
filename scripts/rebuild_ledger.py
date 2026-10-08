#!/usr/bin/env python3
"""Rebuild the public threat ledger from current persisted artifacts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.config import OUTPUT_DIR
from modules.db import load_articles_from_db
from modules.threat_ledger import write_ledger


def _json(path: Path, fallback):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return fallback


def main() -> int:
    articles = load_articles_from_db()
    if not articles:
        articles = _json(OUTPUT_DIR / "daily_latest.json", [])
    clusters = _json(OUTPUT_DIR / "clusters.json", {"clusters": []})
    hunts = _json(OUTPUT_DIR / "hunts.json", {"hunts": []})
    payload = write_ledger(articles, clusters, hunts)
    print(
        f"Ledger rebuilt: {payload['summary']['active_records']} active records, "
        f"{payload['run_change_count']} changes this run"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
