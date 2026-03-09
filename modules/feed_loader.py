# modules/feed_loader.py
import yaml
import logging
from pathlib import Path

def _validate_feed(feed, source_path):
    if not isinstance(feed, dict):
        logging.warning(f"Skipping non-dict feed entry in {source_path}: {feed}")
        return False
    if "url" not in feed or not feed["url"]:
        logging.warning(f"Skipping feed missing required 'url' field in {source_path}: {feed}")
        return False
    return True


def load_feeds_from_files(file_paths):
    feeds = []
    for path in file_paths:
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
                if isinstance(data, list):
                    valid_feeds = [feed for feed in data if _validate_feed(feed, path)]
                    feeds.extend(valid_feeds)
                else:
                    logging.warning(f"{path} does not contain a list of feeds.")
        except Exception as e:
            logging.error(f"Failed to load {path}: {e}")
    return feeds
