import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from modules.config import STATE_DIR, DAILY_BUDGET_USD

COST_FILE = STATE_DIR / "api_costs.json"

# Haiku 4.5 pricing per million tokens (USD)
PRICE_INPUT_PER_MTOK = 0.80
PRICE_OUTPUT_PER_MTOK = 4.00
PRICE_CACHE_READ_PER_MTOK = 0.08
PRICE_CACHE_WRITE_PER_MTOK = 1.00


def _load_costs():
    if not COST_FILE.exists():
        return {"daily": {}, "total_usd": 0.0}
    try:
        with open(COST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {"daily": {}, "total_usd": 0.0}


def _save_costs(data):
    COST_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(COST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _calculate_cost(usage):
    input_tokens = getattr(usage, "input_tokens", 0)
    output_tokens = getattr(usage, "output_tokens", 0)

    cache_read = 0
    cache_creation = 0
    if hasattr(usage, "cache_read_input_tokens"):
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
    if hasattr(usage, "cache_creation_input_tokens"):
        cache_creation = getattr(usage, "cache_creation_input_tokens", 0) or 0

    non_cached_input = input_tokens - cache_read - cache_creation

    cost = (
        (non_cached_input / 1_000_000) * PRICE_INPUT_PER_MTOK
        + (output_tokens / 1_000_000) * PRICE_OUTPUT_PER_MTOK
        + (cache_read / 1_000_000) * PRICE_CACHE_READ_PER_MTOK
        + (cache_creation / 1_000_000) * PRICE_CACHE_WRITE_PER_MTOK
    )
    return cost, input_tokens, output_tokens, cache_read, cache_creation


def track_usage(response):
    usage = getattr(response, "usage", None)
    if not usage:
        return 0.0

    cost, inp, out, cache_r, cache_w = _calculate_cost(usage)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    data = _load_costs()
    day_data = data.get("daily", {}).get(today, {
        "cost_usd": 0.0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "api_calls": 0,
    })

    day_data["cost_usd"] = round(day_data["cost_usd"] + cost, 6)
    day_data["input_tokens"] += inp
    day_data["output_tokens"] += out
    day_data["cache_read_tokens"] += cache_r
    day_data["cache_write_tokens"] += cache_w
    day_data["api_calls"] += 1

    if "daily" not in data:
        data["daily"] = {}
    data["daily"][today] = day_data
    data["total_usd"] = round(data.get("total_usd", 0.0) + cost, 6)

    # Keep only last 90 days
    sorted_days = sorted(data["daily"].keys())
    if len(sorted_days) > 90:
        for old_day in sorted_days[:-90]:
            del data["daily"][old_day]

    _save_costs(data)

    logging.debug(
        f"API cost: ${cost:.4f} (in:{inp} out:{out} "
        f"cache_r:{cache_r} cache_w:{cache_w})"
    )
    return cost


def check_daily_budget():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    data = _load_costs()
    day_data = data.get("daily", {}).get(today, {})
    spent = day_data.get("cost_usd", 0.0)

    if spent >= DAILY_BUDGET_USD:
        logging.warning(
            f"Daily budget exceeded: ${spent:.2f} >= ${DAILY_BUDGET_USD:.2f}. "
            f"Skipping API calls."
        )
        return False
    return True


def get_today_spend():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    data = _load_costs()
    return data.get("daily", {}).get(today, {}).get("cost_usd", 0.0)


def get_total_spend():
    data = _load_costs()
    return data.get("total_usd", 0.0)
