"""Provider-aware token cost accounting and paid-provider budget gates."""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any

from modules.config import DAILY_BUDGET_USD, STATE_DIR
from modules.utils import write_json_atomic

logger = logging.getLogger(__name__)

COST_FILE = STATE_DIR / "api_costs.json"
_cost_lock = threading.Lock()

# Legacy SDK-response pricing retained for track_usage callers.
PRICE_INPUT_PER_MTOK = 0.10
PRICE_OUTPUT_PER_MTOK = 0.50
PRICE_CACHE_READ_PER_MTOK = 0.01
PRICE_CACHE_WRITE_PER_MTOK = 0.125

_MODEL_PRICES: dict[str, tuple[float, float]] = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00),
    "gemini-flash-lite-latest": (0.10, 0.40),
    "gemini-2.5-flash-lite": (0.10, 0.40),
    "openai/gpt-oss-120b": (0.15, 0.60),
}


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _empty_costs() -> dict[str, Any]:
    return {"daily": {}, "total_usd": 0.0}


def _load_costs() -> dict[str, Any]:
    if not COST_FILE.exists():
        return _empty_costs()
    try:
        data = json.loads(COST_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return _empty_costs()
        if not isinstance(data.get("daily"), dict):
            data["daily"] = {}
        if not isinstance(data.get("total_usd"), (int, float)):
            data["total_usd"] = 0.0
        return data
    except (json.JSONDecodeError, OSError):
        return _empty_costs()


def _save_costs(data: dict[str, Any]) -> None:
    write_json_atomic(COST_FILE, data, indent=2, ensure_ascii=False)


def _calculate_cost(usage: Any) -> tuple[float, int, int, int, int]:
    input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
    output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
    cache_read = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
    cache_creation = int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
    non_cached_input = max(0, input_tokens - cache_read - cache_creation)
    cost = (
        non_cached_input * PRICE_INPUT_PER_MTOK
        + output_tokens * PRICE_OUTPUT_PER_MTOK
        + cache_read * PRICE_CACHE_READ_PER_MTOK
        + cache_creation * PRICE_CACHE_WRITE_PER_MTOK
    ) / 1_000_000
    return cost, input_tokens, output_tokens, cache_read, cache_creation


def _zero_cost_providers() -> set[str]:
    return {
        value.strip().casefold()
        for value in os.getenv("LLM_ZERO_COST_PROVIDERS", "").split(",")
        if value.strip()
    }


def provider_is_billable(provider: str) -> bool:
    return provider.casefold() not in _zero_cost_providers()


def _usage_tokens(data: dict[str, Any]) -> tuple[int, int]:
    usage = data.get("usage") if isinstance(data, dict) else None
    if not isinstance(usage, dict):
        return 0, 0
    return (
        int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0),
        int(usage.get("completion_tokens") or usage.get("output_tokens") or 0),
    )


def _model_price(model: str, input_tokens: int) -> tuple[float, float] | None:
    normalized = model.strip().casefold()
    if normalized == "claude-haiku-5-5" and input_tokens > 100_000:
        return 0.50, 2.50
    return _MODEL_PRICES.get(normalized)


def _cost_for(
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
) -> tuple[float, bool]:
    if not provider_is_billable(provider):
        return 0.0, True
    price = _model_price(model, input_tokens)
    if price is None:
        return 0.0, False
    return (
        input_tokens * price[0] + output_tokens * price[1]
    ) / 1_000_000, True


def _day_defaults() -> dict[str, Any]:
    return {
        "cost_usd": 0.0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "api_calls": 0,
        "unpriced_calls": 0,
        "by_provider": {},
        "by_caller": {},
    }


def _normalized_day(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    day = {**_day_defaults(), **raw}
    for field in (
        "cost_usd", "input_tokens", "output_tokens", "cache_read_tokens",
        "cache_write_tokens", "api_calls", "unpriced_calls",
    ):
        if not isinstance(day.get(field), (int, float)):
            day[field] = 0
    if not isinstance(day.get("by_provider"), dict):
        day["by_provider"] = {}
    if not isinstance(day.get("by_caller"), dict):
        day["by_caller"] = {}
    return day


def _provider_defaults(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    result = {
        "cost_usd": raw.get("cost_usd", 0.0),
        "input_tokens": raw.get("input_tokens", 0),
        "output_tokens": raw.get("output_tokens", 0),
        "api_calls": raw.get("api_calls", 0),
    }
    return {
        field: value if isinstance(value, (int, float)) else 0
        for field, value in result.items()
    }


def _add_usage(
    cost: float,
    input_tokens: int,
    output_tokens: int,
    provider: str,
    caller: str | None,
    priced: bool,
) -> None:
    with _cost_lock:
        data = _load_costs()
        daily = data["daily"]
        day = _normalized_day(daily.get(_today()))
        day["cost_usd"] = round(float(day["cost_usd"]) + cost, 6)
        day["input_tokens"] += input_tokens
        day["output_tokens"] += output_tokens
        day["api_calls"] += 1
        day["unpriced_calls"] += 0 if priced else 1

        provider_stats = _provider_defaults(day["by_provider"].get(provider))
        provider_stats["cost_usd"] = round(provider_stats["cost_usd"] + cost, 6)
        provider_stats["input_tokens"] += input_tokens
        provider_stats["output_tokens"] += output_tokens
        provider_stats["api_calls"] += 1
        day["by_provider"][provider] = provider_stats
        if caller:
            day["by_caller"][caller] = day["by_caller"].get(caller, 0) + 1

        daily[_today()] = day
        data["total_usd"] = round(float(data.get("total_usd", 0.0)) + cost, 6)
        for old_day in sorted(daily)[:-90]:
            del daily[old_day]
        _save_costs(data)


def record_provider_usage(
    provider: str,
    model: str,
    data: dict[str, Any],
    caller: str | None = None,
) -> float:
    """Record normalized usage from any configured provider."""
    input_tokens, output_tokens = _usage_tokens(data)
    cost, priced = _cost_for(provider, model, input_tokens, output_tokens)
    _add_usage(cost, input_tokens, output_tokens, provider, caller, priced)
    if not priced:
        logger.warning("No cost price configured for model %s", model)
    return cost


def track_usage(response: Any) -> float:
    """Compatibility path for legacy Anthropic SDK response objects."""
    usage = getattr(response, "usage", None)
    if not usage:
        return 0.0
    cost, inp, out, _cache_r, _cache_w = _calculate_cost(usage)
    _add_usage(cost, inp, out, "legacy", None, True)
    return cost


def check_daily_budget() -> bool:
    spent = get_today_spend()
    if spent >= DAILY_BUDGET_USD:
        logger.warning(
            "Daily paid-provider budget reached: $%.2f >= $%.2f",
            spent, DAILY_BUDGET_USD,
        )
        return False
    return True


def can_use_provider(provider: str) -> bool:
    """Allow free-tier providers after the paid-provider budget is spent."""
    return not provider_is_billable(provider) or check_daily_budget()


def get_today_spend() -> float:
    return float(_load_costs().get("daily", {}).get(_today(), {}).get("cost_usd", 0.0))


def get_total_spend() -> float:
    return float(_load_costs().get("total_usd", 0.0))
