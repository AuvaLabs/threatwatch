import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

from modules.config import STATE_DIR

CACHE_DIR = STATE_DIR / "ai_cache"


def _cache_path(content_hash):
    return CACHE_DIR / f"{content_hash}.json"


def get_cached_result(content_hash):
    path = _cache_path(content_hash)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            entry = json.load(f)
        logging.info(f"Cache hit for {content_hash[:12]}...")
        return entry.get("result")
    except (json.JSONDecodeError, KeyError) as e:
        logging.warning(f"Corrupt cache entry {content_hash[:12]}: {e}")
        path.unlink(missing_ok=True)
        return None


def cache_result(content_hash, result):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "result": result,
        "cached_at": datetime.now(timezone.utc).isoformat(),
    }
    path = _cache_path(content_hash)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(entry, f, ensure_ascii=False)
    except Exception as e:
        logging.error(f"Failed to cache result for {content_hash[:12]}: {e}")


def clear_old_cache(max_age_days=30):
    if not CACHE_DIR.exists():
        return
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    cleared = 0
    for path in CACHE_DIR.glob("*.json"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                entry = json.load(f)
            cached_at = datetime.fromisoformat(entry["cached_at"])
            if cached_at < cutoff:
                path.unlink()
                cleared += 1
        except Exception:
            path.unlink(missing_ok=True)
            cleared += 1

    if cleared:
        logging.info(f"Cleared {cleared} expired cache entries.")
