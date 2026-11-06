#!/usr/bin/env python3
"""Repair persisted ThreatFox links from the authenticated API response."""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.config import FEED_CUTOFF_DAYS
from modules.darkweb_monitor import DARKWEB_SOURCES, _fetch_source
from modules.db import sync_corpus
from modules.output_writer import STATIC_DAILY, load_existing
from modules.utils import write_json_atomic


def _trusted_link(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and parsed.hostname == "threatfox.abuse.ch"
        and parsed.path.startswith("/browse/")
    )


def repair_links(
    articles: list[dict],
    fresh_items: list[dict],
) -> tuple[list[dict], int]:
    """Return a copy with trusted ThreatFox links refreshed by stable hash."""
    replacements = {
        item.get("hash"): item.get("link")
        for item in fresh_items
        if item.get("source") == "darkweb:threatfox"
        and item.get("hash")
        and _trusted_link(item.get("link"))
    }
    repaired = []
    changed = 0
    for article in articles:
        updated = {**article}
        replacement = replacements.get(article.get("hash"))
        if (
            article.get("source") == "darkweb:threatfox"
            and replacement
            and replacement != article.get("link")
        ):
            updated["link"] = replacement
            changed += 1
        repaired.append(updated)
    return repaired, changed


def _fresh_items() -> list[dict]:
    source = next(item for item in DARKWEB_SOURCES if item["name"] == "threatfox")
    cutoff = datetime.now(timezone.utc) - timedelta(days=FEED_CUTOFF_DAYS)
    return _fetch_source(source, cutoff)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="persist repaired links")
    args = parser.parse_args()

    if not os.getenv("THREATFOX_AUTH_KEY", "").strip():
        print(json.dumps({"ok": False, "reason": "THREATFOX_AUTH_KEY is not configured"}))
        return 2

    articles = load_existing(STATIC_DAILY)
    repaired, changed = repair_links(articles, _fresh_items())
    if args.apply and changed:
        write_json_atomic(STATIC_DAILY, repaired, ensure_ascii=False)
        sync_corpus(repaired)
    print(json.dumps({"ok": True, "apply": args.apply, "changed": changed}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
