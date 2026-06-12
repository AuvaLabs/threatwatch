"""Groq / OpenAI-compatible API usage tracker.

The existing ``modules/cost_tracker.py`` was wired into Anthropic SDK
responses only — it reads ``response.usage.input_tokens`` which only
exists on Anthropic's object model. Groq and other OpenAI-compatible
providers return ``{"usage": {"prompt_tokens": N, "completion_tokens": N,
"total_tokens": N}}`` in the JSON response, so none of the pipeline's
real LLM traffic (classification, briefing, regional digests, top
stories, summaries, actor profiles) has ever been counted.

This module records per-key and per-day usage from the Groq response
JSON. Writes to ``data/state/groq_usage.json`` with the shape:

    {
      "daily": {
        "2026-04-22": {
          "total_calls": 1234,
          "total_prompt_tokens": 4_000_000,
          "total_completion_tokens": 800_000,
          "keys": {
            "gsk_xxxxxxxx": {
              "calls": 412,
              "prompt_tokens": 1_300_000,
              "completion_tokens": 260_000
            },
            ...
          },
          "by_caller": {
            "classify": {"calls": 2200, "tokens": 1_500_000},
            "briefing": {"calls": 48,   "tokens": 400_000},
            ...
          }
        }
      }
    }

Stored keys are truncated to a prefix ("gsk_" + first 4 chars of the
secret) + "…" so the full secret never hits disk. Last 90 days retained.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from modules.config import STATE_DIR
from modules.utils import write_json_atomic

USAGE_FILE = STATE_DIR / "groq_usage.json"
_lock = threading.Lock()

_MAX_DAYS_RETAINED = 90


def _mask_key(api_key: str | None) -> str:
    """Return a short, non-reversible identifier for an API key.

    ``gsk_AbCdEfGhIjKl…`` → ``gsk_AbCd…``. Only the first 8 chars of the
    secret are kept so a stolen usage file can't be used to reconstruct
    the real key.
    """
    if not api_key:
        return "unknown"
    # "gsk_" prefix + 4 chars + ellipsis
    prefix = api_key[:8]
    return f"{prefix}…"


def _today_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _load() -> dict[str, Any]:
    if not USAGE_FILE.exists():
        return {"daily": {}}
    try:
        return json.loads(USAGE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"daily": {}}


def _save(data: dict[str, Any]) -> None:
    try:
        write_json_atomic(USAGE_FILE, data, indent=2, ensure_ascii=False)
    except OSError as e:
        # Persist failures must never break the pipeline; tracking is
        # observability, not correctness.
        logger.debug("groq_usage: write failed: %s", e)


def _empty_day() -> dict[str, Any]:
    return {
        "total_calls": 0,
        "total_prompt_tokens": 0,
        "total_completion_tokens": 0,
        "keys": {},
        "by_caller": {},
    }


def record_usage(
    api_key: str | None,
    response_json: dict[str, Any] | None,
    caller: str | None = None,
) -> dict[str, int] | None:
    """Record a single Groq API call.

    Args:
        api_key: The Groq API key used for this call (will be masked).
        response_json: The decoded JSON response body. Must contain the
            OpenAI-style ``usage`` object to actually count; missing
            usage is silently skipped.
        caller: Optional short label for the caller (e.g. "classify",
            "briefing", "summaries"). Used for by-caller aggregation.

    Returns a dict with the counts that were added (for testing), or
    None if the response had no usage data. Never raises — tracking
    failures must not propagate.
    """
    if not response_json or not isinstance(response_json, dict):
        return None
    usage = response_json.get("usage")
    if not isinstance(usage, dict):
        return None

    prompt = int(usage.get("prompt_tokens") or 0)
    completion = int(usage.get("completion_tokens") or 0)
    if prompt == 0 and completion == 0:
        return None

    key_id = _mask_key(api_key)
    today = _today_key()
    added = {"calls": 1, "prompt_tokens": prompt, "completion_tokens": completion}

    with _lock:
        data = _load()
        daily = data.setdefault("daily", {})
        day = daily.setdefault(today, _empty_day())

        # Totals
        day["total_calls"] = day.get("total_calls", 0) + 1
        day["total_prompt_tokens"] = day.get("total_prompt_tokens", 0) + prompt
        day["total_completion_tokens"] = day.get("total_completion_tokens", 0) + completion

        # Per-key
        key_entry = day.setdefault("keys", {}).setdefault(
            key_id, {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0},
        )
        key_entry["calls"] += 1
        key_entry["prompt_tokens"] += prompt
        key_entry["completion_tokens"] += completion

        # Per-caller (optional)
        if caller:
            caller_entry = day.setdefault("by_caller", {}).setdefault(
                caller, {"calls": 0, "tokens": 0},
            )
            caller_entry["calls"] += 1
            caller_entry["tokens"] += prompt + completion

        # Retain last N days only.
        sorted_days = sorted(daily.keys())
        if len(sorted_days) > _MAX_DAYS_RETAINED:
            for old in sorted_days[:-_MAX_DAYS_RETAINED]:
                del daily[old]

        _save(data)

    return added


def get_today_usage() -> dict[str, Any]:
    """Return today's aggregated usage (totals + per-key + per-caller)."""
    data = _load()
    return data.get("daily", {}).get(_today_key(), _empty_day())


def get_usage_for_day(date: str) -> dict[str, Any]:
    """Return aggregated usage for a specific YYYY-MM-DD date."""
    data = _load()
    return data.get("daily", {}).get(date, _empty_day())


def get_usage_summary() -> dict[str, Any]:
    """Return a compact summary suitable for the /api/groq-usage endpoint.

    Shape:
        {
          "today": {...today payload...},
          "last_7d": [{"date": "...", "total_calls": N, "total_tokens": N}, ...],
          "generated_at": "ISO-8601"
        }
    """
    data = _load()
    daily = data.get("daily", {})
    today = _today_key()

    last_7d = []
    for date in sorted(daily.keys(), reverse=True)[:7]:
        day = daily[date]
        last_7d.append({
            "date": date,
            "total_calls": day.get("total_calls", 0),
            "total_prompt_tokens": day.get("total_prompt_tokens", 0),
            "total_completion_tokens": day.get("total_completion_tokens", 0),
        })

    return {
        "today": daily.get(today, _empty_day()),
        "last_7d": last_7d,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
