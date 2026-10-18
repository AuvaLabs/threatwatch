"""Durable quota guard for the shared Model Services subscription."""

from __future__ import annotations

import fcntl
import json
import logging
from datetime import datetime, timezone
from typing import Any

from modules.config import (
    MODEL_SERVICES_LUNA_CALLER_COOLDOWN_SECONDS,
    MODEL_SERVICES_LUNA_CALLERS,
    MODEL_SERVICES_LUNA_DAILY_CALL_LIMIT,
    MODEL_SERVICES_SOL_CALLER_COOLDOWN_SECONDS,
    MODEL_SERVICES_SOL_CALLERS,
    MODEL_SERVICES_SOL_DAILY_CALL_LIMIT,
    STATE_DIR,
)
from modules.utils import write_json_atomic

logger = logging.getLogger(__name__)

USAGE_FILE = STATE_DIR / "model_services_usage.json"
LOCK_FILE = STATE_DIR / "model_services_usage.lock"


def _empty_route() -> dict[str, Any]:
    return {"calls": 0, "by_caller": {}}


def _empty_state(day: str) -> dict[str, Any]:
    return {
        "date": day,
        "routes": {"luna": _empty_route(), "sol": _empty_route()},
    }


def _normalized_route(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _empty_route()
    calls = value.get("calls")
    callers = value.get("by_caller")
    if not isinstance(calls, int) or calls < 0 or not isinstance(callers, dict):
        return _empty_route()
    valid_callers = {
        caller: timestamp
        for caller, timestamp in callers.items()
        if isinstance(caller, str) and isinstance(timestamp, (int, float))
    }
    return {"calls": calls, "by_caller": valid_callers}


def _load_state(day: str) -> dict[str, Any]:
    try:
        data = json.loads(USAGE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_state(day)
    if not isinstance(data, dict) or data.get("date") != day:
        return _empty_state(day)
    routes = data.get("routes")
    if not isinstance(routes, dict):
        return _empty_state(day)
    return {
        "date": day,
        "routes": {
            "luna": _normalized_route(routes.get("luna")),
            "sol": _normalized_route(routes.get("sol")),
        },
    }


def _cooldown_active(
    state: dict[str, Any], caller: str, timestamp: float, cooldown: int,
) -> bool:
    last_attempt = state["by_caller"].get(caller)
    if not isinstance(last_attempt, (int, float)):
        return False
    elapsed = timestamp - float(last_attempt)
    return elapsed < cooldown


def _route_policy(route: str) -> tuple[frozenset[str], int, int] | None:
    policies = {
        "luna": (
            MODEL_SERVICES_LUNA_CALLERS,
            MODEL_SERVICES_LUNA_DAILY_CALL_LIMIT,
            MODEL_SERVICES_LUNA_CALLER_COOLDOWN_SECONDS,
        ),
        "sol": (
            MODEL_SERVICES_SOL_CALLERS,
            MODEL_SERVICES_SOL_DAILY_CALL_LIMIT,
            MODEL_SERVICES_SOL_CALLER_COOLDOWN_SECONDS,
        ),
    }
    return policies.get(route)


def claim(
    route: str, caller: str | None, *, now: datetime | None = None,
) -> bool:
    """Atomically reserve one gateway attempt when caller and budget allow it.

    Attempts are counted before the network request. This fail-closed behavior
    protects the shared subscription even when upstream requests time out.
    """
    policy = _route_policy(route)
    if policy is None:
        return False
    callers, daily_limit, cooldown = policy
    if not caller or caller not in callers or daily_limit <= 0:
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
            route_state = state["routes"][route]
            if route_state["calls"] >= daily_limit:
                return False
            if _cooldown_active(route_state, caller, timestamp, cooldown):
                return False
            next_route = {
                **route_state,
                "calls": route_state["calls"] + 1,
                "by_caller": {**route_state["by_caller"], caller: timestamp},
            }
            next_state = {
                **state,
                "routes": {**state["routes"], route: next_route},
            }
            write_json_atomic(USAGE_FILE, next_state, indent=2)
            return True
    except OSError as exc:
        logger.warning("Model Services quota state unavailable: %s", exc)
        return False
