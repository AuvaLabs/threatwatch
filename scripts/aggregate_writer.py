import os
import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent / "data" / "aggregated"
HOURLY_DIR = Path(__file__).parent.parent / "data" / "output" / "hourly"
DAILY_DIR = Path(__file__).parent.parent / "data" / "output" / "daily"

AGGREGATED_FILE = BASE_DIR / "all_cyberattacks.json"


def load_json_files(directory):
    entries = []
    if not directory.exists():
        return entries

    for file in sorted(directory.glob("*.json")):
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                entries.extend(data)
        except Exception as e:
            print(f"Error reading {file.name}: {e}")
    return entries


def save_aggregated_json(entries):
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    with open(AGGREGATED_FILE, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
    print(f"[Aggregator] Saved aggregated data to {AGGREGATED_FILE}")


def aggregate_all():
    print("[Aggregator] Aggregating from hourly and daily data...")
    all_entries = load_json_files(HOURLY_DIR)
    all_entries += load_json_files(DAILY_DIR)

    # Deduplicate by hash
    seen_hashes = set()
    unique_entries = []
    for entry in all_entries:
        key = entry.get("hash") or entry.get("link")
        if not key:
            continue
        if key in seen_hashes:
            continue
        seen_hashes.add(key)
        unique_entries.append(entry)

    # Sort chronologically
    unique_entries.sort(key=lambda x: x.get("processed_at", ""), reverse=True)
    save_aggregated_json(unique_entries)


if __name__ == "__main__":
    aggregate_all()
