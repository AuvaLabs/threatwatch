import yaml
import logging
import feedparser
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")


def load_feeds_from_yaml(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("feeds", [])
            return []
    except Exception as e:
        logging.error(f"Failed to load {filepath.name}: {e}")
        return []


def validate_feed(url):
    try:
        d = feedparser.parse(url)
        status = d.get("status", "?")
        count = len(d.entries)
        if count > 0:
            logging.info(f"PASS {url} ({count} entries, status {status})")
            return True
        else:
            logging.warning(f"WARN {url} (0 entries, status {status})")
            return False
    except Exception as e:
        logging.error(f"FAIL {url}: {e}")
        return False


def main():
    config_dir = Path("config")
    files = ["feeds_bing.yaml", "feeds_google.yaml", "feeds_native.yaml"]

    total = 0
    passed = 0
    failed = 0

    for file_name in files:
        logging.info(f"\n--- Validating feeds in {file_name} ---")
        path = config_dir / file_name
        feeds = load_feeds_from_yaml(path)
        if not feeds:
            logging.warning(f"No feeds loaded from {file_name}")
            continue
        for feed in feeds:
            total += 1
            if validate_feed(feed["url"]):
                passed += 1
            else:
                failed += 1

    logging.info(f"\n--- Results: {passed}/{total} passed, {failed} failed ---")


if __name__ == "__main__":
    main()
