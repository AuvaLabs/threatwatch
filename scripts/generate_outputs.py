import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from feedgen.feed import FeedGenerator

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.config import SITE_URL, DATA_DIR, OUTPUT_DIR

AGGREGATED_FILE = DATA_DIR / "aggregated" / "all_cyberattacks.json"
RSS_FILE = OUTPUT_DIR / "rss_cyberattacks.xml"
DASHBOARD_FILE = OUTPUT_DIR / "dashboard.md"

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")


def load_aggregated():
    if not AGGREGATED_FILE.exists():
        logging.error(
            f"Aggregated file not found: {AGGREGATED_FILE}. "
            "Run scripts/aggregate_writer.py first."
        )
        return []
    with open(AGGREGATED_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def generate_rss(entries):
    fg = FeedGenerator()
    fg.id(f"{SITE_URL}/threatdigest")
    fg.title("ThreatDigest Hub - Latest Cyberattacks")
    fg.link(href=SITE_URL, rel="alternate")
    fg.language("en")

    for entry in entries[:50]:
        fe = fg.add_entry()
        fe.id(entry.get("hash", entry.get("link", "")))
        fe.title(entry.get("title", "No Title"))
        fe.link(href=entry.get("link", "#"))
        fe.published(entry.get("published", datetime.now(timezone.utc).isoformat()))
        category = entry.get("category", "Unknown")
        source = entry.get("source", "")
        fe.description(f"{category} | Source: {source}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    fg.rss_file(str(RSS_FILE))
    logging.info(f"RSS generated at {RSS_FILE}")


def generate_dashboard_md(entries):
    with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
        f.write("# ThreatDigest Cyberattack Feed\n\n")
        f.write(f"Updated: {datetime.now(timezone.utc).isoformat()} UTC\n\n")
        f.write("| Date | Title | Category | Source |\n")
        f.write("|------|-------|----------|--------|\n")
        for entry in entries[:100]:
            date = entry.get("published", "")[:10]
            title = entry.get("title", "").replace("|", "").replace("\n", " ").strip()
            link = entry.get("link", "#")
            category = entry.get("category", "Unknown")
            source = entry.get("source", "n/a")
            f.write(f"| {date} | [{title}]({link}) | {category} | {source} |\n")

    logging.info(f"Markdown dashboard saved to {DASHBOARD_FILE}")


def main():
    entries = load_aggregated()
    if not entries:
        logging.warning("No entries found for output generation.")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    generate_rss(entries)
    generate_dashboard_md(entries)


if __name__ == "__main__":
    main()
