#!/usr/bin/env python3
"""Feed health reporter and live validator.

Usage:
    python scripts/validate_feeds.py           # show persisted health report
    python scripts/validate_feeds.py --live    # re-validate all feeds right now
    python scripts/validate_feeds.py --dead    # show only dead/suspect/stale feeds
"""

import argparse
import logging
import sys
from pathlib import Path

import feedparser
import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.feed_health import load_health, print_report, record_fetch

CONFIG_DIR = BASE_DIR / "config"
FEED_FILES = [
    CONFIG_DIR / "feeds_native.yaml",
    CONFIG_DIR / "feeds_google.yaml",
    CONFIG_DIR / "feeds_bing.yaml",
]


def load_all_feeds() -> list:
    feeds = []
    for path in FEED_FILES:
        if not path.exists():
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                feeds.extend(data)
            elif isinstance(data, dict):
                feeds.extend(data.get("feeds", []))
        except Exception as e:
            logging.warning(f"Could not load {path}: {e}")
    return feeds


def live_validate(feeds: list, timeout: int = 12) -> None:
    """Fetch every feed right now and update health state."""
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://",  HTTPAdapter(max_retries=retry))
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    passed = failed = quiet = 0
    for feed in feeds:
        url = feed.get("url", "")
        if not url:
            continue
        try:
            resp = session.get(url, timeout=timeout)
            resp.raise_for_status()
            parsed = feedparser.parse(resp.content)
            count  = len(parsed.entries)
            record_fetch(url, success=True, entry_count=count)
            if count > 0:
                logging.info(f"PASS  {count:>3} entries  {url}")
                passed += 1
            else:
                logging.info(f"QUIET   0 entries  {url}")
                quiet += 1
        except Exception as e:
            logging.warning(f"FAIL               {url}  ({e})")
            record_fetch(url, success=False, entry_count=0)
            failed += 1

    print(f"\nLive check done — {passed} ok, {quiet} quiet (no recent entries), {failed} failed\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatWatch feed health tool")
    parser.add_argument("--live",    action="store_true", help="Re-validate all feeds now")
    parser.add_argument("--dead",    action="store_true", help="Show only degraded feeds")
    parser.add_argument("--timeout", type=int, default=12, help="Per-feed timeout (live mode)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s | %(message)s",
    )

    feeds = load_all_feeds()
    logging.info(f"Feeds in config: {len(feeds)}")

    if args.live:
        print(f"\nRunning live validation of {len(feeds)} feeds (timeout={args.timeout}s)…")
        live_validate(feeds, timeout=args.timeout)

    if args.dead:
        data = load_health()
        bad  = [e for e in data.values() if e.get("status") in ("dead", "suspect", "stale", "error")]
        if not bad:
            print("No degraded feeds found.")
        else:
            print(f"\n{'='*62}")
            print(f"DEGRADED FEEDS ({len(bad)} total)")
            print(f"{'='*62}")
            for e in sorted(bad, key=lambda x: x.get("consecutive_errors", 0), reverse=True):
                errs   = e.get("consecutive_errors", 0)
                status = e.get("status", "?").upper()
                last_ok = (e.get("last_success") or "never")[:10]
                print(f"  [{status:>7}] {errs:>3} errors | last ok: {last_ok} | {e['url']}")
            print()
    else:
        print_report()


if __name__ == "__main__":
    main()
