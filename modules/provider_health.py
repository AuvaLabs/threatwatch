"""Persistent health and circuit-breaker state for intelligence providers."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from modules.config import STATE_DIR


PROVIDER_HEALTH_FILE = STATE_DIR / "provider_health.json"
_SAFE_REASON = re.compile(r"^[a-z0-9_]{1,80}$")
logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_reason(value: str, fallback: str) -> str:
    normalized = str(value).strip().lower()
    return normalized if _SAFE_REASON.fullmatch(normalized) else fallback


def _load() -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(PROVIDER_HEALTH_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(name): dict(entry)
        for name, entry in payload.items()
        if isinstance(entry, dict)
    }


def _save(payload: dict[str, dict[str, Any]]) -> None:
    try:
        PROVIDER_HEALTH_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(f"{PROVIDER_HEALTH_FILE}.tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        temporary.replace(PROVIDER_HEALTH_FILE)
    except OSError as error:
        logger.warning("Provider health state could not be written: %s", error)


def record_success(name: str, *, item_count: int) -> None:
    payload = _load()
    payload[name] = {
        "status": "healthy",
        "checked_at": _now().isoformat(),
        "last_success": _now().isoformat(),
        "item_count": max(0, int(item_count)),
        "consecutive_failures": 0,
    }
    _save(payload)


def record_failure(
    name: str,
    error: str,
    *,
    cooldown_seconds: int,
    failure_threshold: int = 1,
) -> None:
    payload = _load()
    previous = payload.get(name, {})
    now = _now()
    consecutive_failures = int(previous.get("consecutive_failures", 0)) + 1
    should_suspend = (
        cooldown_seconds > 0
        and consecutive_failures >= max(1, int(failure_threshold))
    )
    entry: dict[str, Any] = {
        "status": "suspended" if should_suspend else "degraded",
        "checked_at": now.isoformat(),
        "error": _safe_reason(error, "provider_error"),
        "consecutive_failures": consecutive_failures,
    }
    if previous.get("last_success"):
        entry["last_success"] = previous["last_success"]
    if should_suspend:
        entry["retry_after"] = (
            now + timedelta(seconds=max(0, cooldown_seconds))
        ).isoformat()
    payload[name] = entry
    _save(payload)


def record_disabled(name: str, reason: str) -> None:
    payload = _load()
    payload[name] = {
        "status": "disabled",
        "checked_at": _now().isoformat(),
        "reason": _safe_reason(reason, "operator_disabled"),
        "consecutive_failures": 0,
    }
    _save(payload)


def is_suspended(name: str) -> bool:
    entry = _load().get(name, {})
    if entry.get("status") != "suspended":
        return False
    try:
        retry_after = datetime.fromisoformat(str(entry["retry_after"]).replace("Z", "+00:00"))
        if retry_after.tzinfo is None:
            retry_after = retry_after.replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError):
        return False
    return retry_after > _now()


def get_provider_health() -> dict[str, Any]:
    providers = _load()
    statuses = [entry.get("status") for entry in providers.values()]
    return {
        "total": len(providers),
        "healthy": statuses.count("healthy"),
        "degraded": statuses.count("degraded"),
        "suspended": statuses.count("suspended"),
        "disabled": statuses.count("disabled"),
        "providers": providers,
        "generated_at": _now().isoformat(),
    }
