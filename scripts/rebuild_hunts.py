#!/usr/bin/env python3
"""Rebuild the hunt artifact from the current corpus and incident clusters."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.config import OUTPUT_DIR
from modules.db import load_articles_from_db
from modules.hunt_engine import write_hunts
from modules.ioc_enrichment import refresh_observable_enrichments
from modules.safe_http import install_ssrf_guard


def main() -> int:
    install_ssrf_guard()
    articles = load_articles_from_db()
    if not articles:
        corpus_path = OUTPUT_DIR / "daily_latest.json"
        try:
            loaded = json.loads(corpus_path.read_text(encoding="utf-8"))
            articles = loaded if isinstance(loaded, list) else []
        except (FileNotFoundError, json.JSONDecodeError):
            articles = []
    cluster_path = OUTPUT_DIR / "clusters.json"
    try:
        clusters = json.loads(cluster_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"Unable to load incident clusters: {exc}", file=sys.stderr)
        return 1
    enrichments = refresh_observable_enrichments(articles)
    payload = write_hunts(articles, clusters, enrichments)
    print(
        f"Wrote {payload['qualified_count']} qualified hunts and "
        f"{payload['lead_count']} developing leads to {OUTPUT_DIR / 'hunts.json'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
