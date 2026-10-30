#!/usr/bin/env python3
"""Validate or rebuild incidents, hunts, and ledger from the persisted corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.config import OUTPUT_DIR
from modules.db import load_articles_from_db
from modules.hunt_engine import build_hunts
from modules.incident_records import build_incident_records
from modules.operational_artifact_health import write_operational_artifact_status
from modules.threat_ledger import build_ledger
from modules.utils import write_json_atomic


def _json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return fallback


def build_artifacts(output_dir: Path = OUTPUT_DIR) -> tuple[dict, dict, dict]:
    articles = load_articles_from_db()
    if not articles:
        articles = _json(output_dir / "daily_latest.json", [])
    clusters = _json(output_dir / "clusters.json", None)
    if not isinstance(articles, list) or not isinstance(clusters, dict):
        raise ValueError("persisted corpus or cluster artifact is invalid")
    previous_incidents = _json(output_dir / "incidents-v2.json", None)
    incidents = build_incident_records(articles, previous=previous_incidents)
    hunts = build_hunts(articles, clusters)
    previous = _json(output_dir / "threat_ledger.json", None)
    ledger = build_ledger(articles, clusters, hunts, previous=previous)
    valid = all(isinstance(payload.get(collection), list) for payload, collection in (
        (incidents, "records"), (hunts, "hunts"), (ledger, "records"),
    ))
    if not valid:
        raise ValueError("generated analyst artifact has an invalid shape")
    return incidents, hunts, ledger


def publish_artifacts(output_dir: Path = OUTPUT_DIR) -> tuple[dict, dict, dict]:
    incidents, hunts, ledger = build_artifacts(output_dir)
    write_json_atomic(output_dir / "incidents-v2.json", incidents, indent=2)
    write_json_atomic(output_dir / "hunts.json", hunts, indent=2)
    write_json_atomic(output_dir / "threat_ledger.json", ledger)
    write_operational_artifact_status(
        {"incidents": {"ok": True}, "hunts": {"ok": True}, "ledger": {"ok": True}},
        state_dir=output_dir.parent / "state",
    )
    return incidents, hunts, ledger


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="publish validated artifacts")
    args = parser.parse_args()
    incidents, hunts, ledger = publish_artifacts() if args.write else build_artifacts()
    print(json.dumps({
        "ok": True,
        "write": args.write,
        "incidents": len(incidents["records"]),
        "high_priority_incidents": incidents["summary"]["high_priority"],
        "hunts": len(hunts["hunts"]),
        "qualified_hunts": hunts["qualified_count"],
        "ledger_records": len(ledger["records"]),
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
