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
from modules.keyword_data import _NOISE_PATTERNS


def filter_noise_articles(articles: list[dict]) -> list[dict]:
    """Remove articles whose titles match the current noise policy."""
    return [
        article
        for article in articles
        if not any(
            pattern.search(str(article.get("title", "")))
            for pattern in _NOISE_PATTERNS
        )
    ]


def repair_articles(articles: list[dict], *, filter_noise: bool = False) -> list[dict]:
    """Apply the same normalization, date, and dedup rules as ingestion."""
    candidates = filter_noise_articles(articles) if filter_noise else articles
    return _merge_articles([], candidates)


def _backup(source: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = source.parent / "backups" / f"daily_latest.pre-contract-{stamp}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="persist the repaired corpus")
    parser.add_argument(
        "--filter-noise",
        action="store_true",
        help="remove articles whose titles match the current noise policy",
    )
    parser.add_argument("--path", type=Path, default=STATIC_DAILY)
    args = parser.parse_args(argv)

    articles = load_existing(args.path)
    candidates = filter_noise_articles(articles) if args.filter_noise else articles
    repaired = repair_articles(candidates)
    report = {
        "input_articles": len(articles),
        "output_articles": len(repaired),
        "removed_articles": len(articles) - len(repaired),
        "noise_articles_removed": len(articles) - len(candidates),
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
