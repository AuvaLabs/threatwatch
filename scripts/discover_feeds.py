#!/usr/bin/env python3
"""Feed discovery — finds new security RSS feeds not yet in our config.

Workflow:
  1. Load existing feed URLs from config/*.yaml (baseline)
  2. Fetch OPML / plaintext-URL sources listed in config/discover_sources.yaml
  3. Collect manual candidate seeds from the same file
  4. Validate each candidate: live HTTP, entry count, recency
  5. Score by freshness and volume
  6. Write ranked output to data/state/feed_candidates.yaml

Run manually or via weekly cron. Never auto-adds feeds — outputs for human review.

Usage:
    python scripts/discover_feeds.py [--verbose] [--timeout N]
"""

import argparse
import logging
import re
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path

import feedparser
import requests
import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.config import STATE_DIR

CONFIG_DIR       = BASE_DIR / "config"
CANDIDATES_FILE  = STATE_DIR / "feed_candidates.yaml"
DISCOVER_SOURCES = CONFIG_DIR / "discover_sources.yaml"
FEED_FILES       = [
    CONFIG_DIR / "feeds_native.yaml",
    CONFIG_DIR / "feeds_google.yaml",
    CONFIG_DIR / "feeds_bing.yaml",
]

_VALIDATE_TIMEOUT  = 12   # seconds per candidate feed fetch
_MAX_WORKERS       = 10
_RECENCY_DAYS      = 14   # candidate must have had an article within this window
_MIN_ENTRIES       = 1    # minimum entries for a candidate to pass


# ── load existing feeds ─────────────────────────────────────────────────────

def _load_yaml_feeds(path: Path) -> list[str]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [f["url"] for f in data if isinstance(f, dict) and "url" in f]
        if isinstance(data, dict):
            feeds = data.get("feeds", [])
            return [f["url"] for f in feeds if isinstance(f, dict) and "url" in f]
    except Exception:
        pass
    return []


def load_existing_urls() -> set[str]:
    urls: set[str] = set()
    for path in FEED_FILES:
        if path.exists():
            urls.update(_load_yaml_feeds(path))
    return urls


# ── discover sources ─────────────────────────────────────────────────────────

def load_discover_config() -> dict:
    if not DISCOVER_SOURCES.exists():
        return {"sources": [], "manual_candidates": []}
    try:
        return yaml.safe_load(DISCOVER_SOURCES.read_text(encoding="utf-8")) or {}
    except Exception as e:
        logging.warning(f"Could not load discover_sources.yaml: {e}")
        return {"sources": [], "manual_candidates": []}


def _fetch_opml(url: str, timeout: int = 10) -> list[str]:
    """Parse an OPML file and return xmlUrl attributes."""
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "ThreatWatch/1.0"})
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        return [
            el.get("xmlUrl") or el.get("xmlurl") or ""
            for el in root.iter("outline")
            if el.get("xmlUrl") or el.get("xmlurl")
        ]
    except Exception as e:
        logging.warning(f"OPML fetch failed ({url}): {e}")
        return []


def _extract_urls_from_text(text: str) -> list[str]:
    """Extract http/https URLs from arbitrary text (README, plaintext lists)."""
    return re.findall(r'https?://[^\s\)>\"\'\]\}]+(?:rss|feed|atom|xml)[^\s\)>\"\'\]\}]*', text, re.IGNORECASE)


def _fetch_txt_urls(url: str, timeout: int = 10) -> list[str]:
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "ThreatWatch/1.0"})
        resp.raise_for_status()
        return _extract_urls_from_text(resp.text)
    except Exception as e:
        logging.warning(f"Text URL fetch failed ({url}): {e}")
        return []


def gather_candidates(discover_cfg: dict, existing_urls: set[str]) -> list[dict]:
    """Collect candidate feed URLs from all discovery sources and manual seeds."""
    candidates: list[dict] = []
    seen: set[str] = set(existing_urls)

    def _add(url: str, label: str) -> None:
        url = url.strip().rstrip(".,;")
        if url and url not in seen and url.startswith("http"):
            seen.add(url)
            candidates.append({"url": url, "label": label})

    # OPML / text sources
    for source in discover_cfg.get("sources", []):
        src_url = source.get("url", "")
        fmt     = source.get("format", "opml")
        label   = source.get("label", src_url)
        logging.info(f"Fetching discovery source: {label}")

        if fmt == "opml":
            for u in _fetch_opml(src_url):
                _add(u, label)
        else:  # txt_urls
            for u in _fetch_txt_urls(src_url):
                _add(u, label)

    # Manual seeds
    for seed in discover_cfg.get("manual_candidates", []):
        _add(seed.get("url", ""), seed.get("label", "manual"))

    return candidates


# ── validation ───────────────────────────────────────────────────────────────

def _validate_candidate(url: str, timeout: int) -> dict | None:
    """Fetch and evaluate a candidate feed. Returns a result dict or None on failure."""
    try:
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/rss+xml, application/xml, text/xml, */*",
        })
        resp.raise_for_status()

        parsed = feedparser.parse(resp.content)
        entries = parsed.entries
        if len(entries) < _MIN_ENTRIES:
            return None

        cutoff = datetime.now(timezone.utc) - timedelta(days=_RECENCY_DAYS)
        recent = 0
        newest = None

        for e in entries:
            pub = e.get("published") or e.get("updated") or ""
            if pub:
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(pub)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    if not newest or dt > newest:
                        newest = dt
                    if dt >= cutoff:
                        recent += 1
                except Exception:
                    pass

        if recent == 0:
            return None  # no recent content

        feed_title = getattr(parsed.feed, "title", "") or ""
        return {
            "url":         url,
            "title":       feed_title,
            "total":       len(entries),
            "recent_14d":  recent,
            "newest":      newest.isoformat() if newest else "",
            "score":       recent * 3 + len(entries),
        }

    except Exception:
        return None


def validate_candidates(candidates: list[dict], timeout: int) -> list[dict]:
    results = []
    logging.info(f"Validating {len(candidates)} candidate feeds...")

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        futures = {
            executor.submit(_validate_candidate, c["url"], timeout): c
            for c in candidates
        }
        for future in as_completed(futures):
            candidate = futures[future]
            try:
                result = future.result()
                if result:
                    result["label"] = candidate.get("label", "")
                    results.append(result)
                    logging.info(
                        f"  PASS [{result['recent_14d']} recent] {result['url']}"
                    )
                else:
                    logging.debug(f"  SKIP (no recent content): {candidate['url']}")
            except Exception as e:
                logging.debug(f"  SKIP (error): {candidate['url']} — {e}")

    return sorted(results, key=lambda x: x["score"], reverse=True)


# ── output ───────────────────────────────────────────────────────────────────

def write_candidates(results: list[dict]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    output = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "note": (
            "Candidate feeds not yet in config/feeds_native.yaml. "
            "Review and add manually. Sorted by score (recent_14d * 3 + total entries)."
        ),
        "candidates": results,
    }
    CANDIDATES_FILE.write_text(
        yaml.dump(output, allow_unicode=True, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    logging.info(f"Wrote {len(results)} candidates to {CANDIDATES_FILE}")


def print_summary(results: list[dict]) -> None:
    if not results:
        print("\nNo new candidate feeds found.\n")
        return

    sep = "=" * 70
    print(f"\n{sep}")
    print(f"FEED DISCOVERY RESULTS  {datetime.now(timezone.utc).isoformat()[:10]}")
    print(f"{len(results)} new candidate(s) not in current config")
    print(sep)
    for i, r in enumerate(results[:30], 1):
        title = r.get("title") or r["url"]
        print(f"\n  {i:>2}. {title}")
        print(f"      URL     : {r['url']}")
        print(f"      Recent  : {r['recent_14d']} articles in 14d  |  Total: {r['total']}")
        print(f"      Newest  : {r.get('newest', '')[:16]}")
        print(f"      Source  : {r.get('label', '')}")
    print(f"\n  Full list saved to: {CANDIDATES_FILE}")
    print(f"{sep}\n")


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Discover new security RSS feed candidates")
    parser.add_argument("--verbose", action="store_true", help="Debug logging")
    parser.add_argument("--timeout", type=int, default=_VALIDATE_TIMEOUT,
                        help=f"Per-feed validation timeout in seconds (default: {_VALIDATE_TIMEOUT})")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s | %(message)s",
    )

    existing_urls  = load_existing_urls()
    logging.info(f"Existing feeds in config: {len(existing_urls)}")

    discover_cfg   = load_discover_config()
    candidates     = gather_candidates(discover_cfg, existing_urls)
    logging.info(f"Unique new candidates to validate: {len(candidates)}")

    if not candidates:
        logging.info("No new candidates found.")
        return

    results = validate_candidates(candidates, timeout=args.timeout)
    write_candidates(results)
    print_summary(results)


if __name__ == "__main__":
    main()
