"""Durable quota guard for the shared Model Services subscription."""

from __future__ import annotations

import fcntl
import json
import logging
from datetime import datetime, timezone
from typing import Any

from modules.config import (
    MODEL_SERVICES_CALLER_COOLDOWN_SECONDS,
    MODEL_SERVICES_CALLERS,
    MODEL_SERVICES_DAILY_CALL_LIMIT,
    STATE_DIR,
)
from modules.utils import write_json_atomic

logger = logging.getLogger(__name__)

USAGE_FILE = STATE_DIR / "model_services_usage.json"
LOCK_FILE = STATE_DIR / "model_services_usage.lock"


def _empty_state(day: str) -> dict[str, Any]:
    return {"date": day, "calls": 0, "by_caller": {}}


def _load_state(day: str) -> dict[str, Any]:
    try:
        data = json.loads(USAGE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_state(day)
    if not isinstance(data, dict) or data.get("date") != day:
        return _empty_state(day)
    calls = data.get("calls")
    callers = data.get("by_caller")
    if not isinstance(calls, int) or calls < 0 or not isinstance(callers, dict):
        return _empty_state(day)
    return {"date": day, "calls": calls, "by_caller": callers}


def _cooldown_active(state: dict[str, Any], caller: str, timestamp: float) -> bool:
    last_attempt = state["by_caller"].get(caller)
    if not isinstance(last_attempt, (int, float)):
        return False
    elapsed = timestamp - float(last_attempt)
    return elapsed < MODEL_SERVICES_CALLER_COOLDOWN_SECONDS


def claim(caller: str | None, *, now: datetime | None = None) -> bool:
    """Atomically reserve one gateway attempt when caller and budget allow it.

    Attempts are counted before the network request. This fail-closed behavior
    protects the shared subscription even when upstream requests time out.
    """
    if (
        not caller
        or caller not in MODEL_SERVICES_CALLERS
        or MODEL_SERVICES_DAILY_CALL_LIMIT <= 0
    ):
        return False

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    day = current.strftime("%Y-%m-%d")
    timestamp = current.timestamp()

    try:
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOCK_FILE.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle, fcntl.LOCK_EX)
            state = _load_state(day)
            if state["calls"] >= MODEL_SERVICES_DAILY_CALL_LIMIT:
                return False
            if _cooldown_active(state, caller, timestamp):
                return False
            next_state = {
                **state,
                "calls": state["calls"] + 1,
                "by_caller": {**state["by_caller"], caller: timestamp},
            }
            write_json_atomic(USAGE_FILE, next_state, indent=2)
            return True
    except OSError as exc:
        logger.warning("Model Services quota state unavailable: %s", exc)
        return False
