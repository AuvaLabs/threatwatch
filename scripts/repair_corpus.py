#!/usr/bin/env python3
"""Audit and optionally repair the persisted article corpus."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.output_writer import STATIC_DAILY, _merge_articles, load_existing, persist_corpus


def repair_articles(articles: list[dict]) -> list[dict]:
    """Apply the same normalization, date, and dedup rules as ingestion."""
    return _merge_articles([], articles)


def _backup(source: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = source.parent / "backups" / f"daily_latest.pre-contract-{stamp}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="persist the repaired corpus")
    parser.add_argument("--path", type=Path, default=STATIC_DAILY)
    args = parser.parse_args(argv)

    articles = load_existing(args.path)
    repaired = repair_articles(articles)
    report = {
        "input_articles": len(articles),
        "output_articles": len(repaired),
        "removed_articles": len(articles) - len(repaired),
        "source_names_present": sum(bool(item.get("source_name")) for item in repaired),
        "summaries_present": sum(bool(item.get("summary")) for item in repaired),
        "applied": args.apply,
    }
    if args.apply:
        if args.path != STATIC_DAILY:
            raise ValueError("--apply is restricted to the configured daily corpus")
        report["backup"] = str(_backup(args.path))
        persist_corpus(repaired)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
