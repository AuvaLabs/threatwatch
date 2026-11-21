"""Persistent, public-safe reliability state for the shared LLM chain."""

from __future__ import annotations

import fcntl
import json
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from modules.config import STATE_DIR


STATE_FILE = STATE_DIR / "llm_reliability.json"
LOCK_FILE = STATE_DIR / "llm_reliability.lock"
_SCHEMA_VERSION = 1
_FAILURE_KINDS = {
    "empty_response",
    "invalid_response",
    "rate_limit",
    "server_error",
    "transport_error",
}
logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime:
    current = value or _utc_now()
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def _nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def _empty_state(now: datetime) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "day": now.date().isoformat(),
        "requests": {"total": 0, "successful": 0, "failed": 0},
        "providers": {},
    }


def _load(path: Path, now: datetime) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return _empty_state(now)
    if not isinstance(payload, dict) or payload.get("schema_version") != _SCHEMA_VERSION:
        return _empty_state(now)
    if payload.get("day") != now.date().isoformat():
        fresh = _empty_state(now)
        providers = payload.get("providers")
        if isinstance(providers, dict):
            fresh["providers"] = {
                str(name): {
                    "attempts": 0,
                    "successes": 0,
                    "failures": 0,
                    "rate_limits": 0,
                    "empty_responses": 0,
                    "consecutive_failures": _nonnegative_int(
                        entry.get("consecutive_failures", 0),
                    ),
                    "cooldown_until": entry.get("cooldown_until"),
                    "last_success": entry.get("last_success"),
                    "last_failure": entry.get("last_failure"),
                }
                for name, entry in providers.items()
                if isinstance(entry, dict)
            }
        return fresh
    payload.setdefault("requests", {"total": 0, "successful": 0, "failed": 0})
    payload.setdefault("providers", {})
    return payload


def _save(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    temporary.replace(path)


@contextmanager
def _locked_state(
    now: datetime,
    state_file: Path | None = None,
) -> Iterator[tuple[Path, dict[str, Any]]]:
    path = state_file or STATE_FILE
    lock_path = LOCK_FILE if path == STATE_FILE else Path(f"{path}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield path, _load(path, now)


def _provider_entry(payload: dict[str, Any], name: str) -> dict[str, Any]:
    providers = payload.setdefault("providers", {})
    entry = providers.setdefault(str(name), {})
    defaults = {
        "attempts": 0,
        "successes": 0,
        "failures": 0,
        "rate_limits": 0,
        "empty_responses": 0,
        "consecutive_failures": 0,
        "cooldown_until": None,
        "last_success": None,
        "last_failure": None,
    }
    for key, value in defaults.items():
        entry.setdefault(key, value)
    for key in (
        "attempts",
        "successes",
        "failures",
        "rate_limits",
        "empty_responses",
        "consecutive_failures",
    ):
        entry[key] = _nonnegative_int(entry.get(key))
    return entry


def record_provider_failure(
    name: str,
    failure_kind: str,
    *,
    threshold: int,
    cooldown_seconds: int,
    now: datetime | None = None,
) -> None:
    current = _as_utc(now)
    kind = failure_kind if failure_kind in _FAILURE_KINDS else "invalid_response"
    try:
        with _locked_state(current) as (path, payload):
            entry = _provider_entry(payload, name)
            entry["attempts"] += 1
            entry["failures"] += 1
            entry["consecutive_failures"] += 1
            entry["last_failure"] = current.isoformat()
            if kind == "rate_limit":
                entry["rate_limits"] += 1
            if kind == "empty_response":
                entry["empty_responses"] += 1
            if (
                cooldown_seconds > 0
                and entry["consecutive_failures"] >= max(1, int(threshold))
            ):
                entry["cooldown_until"] = (
                    current + timedelta(seconds=max(0, int(cooldown_seconds)))
                ).isoformat()
            _save(path, payload)
    except OSError as exc:
        logger.warning("LLM reliability state could not be written: %s", exc)


def record_provider_success(name: str, *, now: datetime | None = None) -> None:
    current = _as_utc(now)
    try:
        with _locked_state(current) as (path, payload):
            entry = _provider_entry(payload, name)
            entry["attempts"] += 1
            entry["successes"] += 1
            entry["consecutive_failures"] = 0
            entry["cooldown_until"] = None
            entry["last_success"] = current.isoformat()
            _save(path, payload)
    except OSError as exc:
        logger.warning("LLM reliability state could not be written: %s", exc)


def record_request_result(
    success: bool,
    caller: str | None = None,
    *,
    now: datetime | None = None,
) -> None:
    del caller
    current = _as_utc(now)
    try:
        with _locked_state(current) as (path, payload):
            requests = payload["requests"]
            requests["total"] = _nonnegative_int(requests.get("total", 0)) + 1
            key = "successful" if success else "failed"
            requests[key] = _nonnegative_int(requests.get(key, 0)) + 1
            _save(path, payload)
    except OSError as exc:
        logger.warning("LLM reliability state could not be written: %s", exc)


def _parse_timestamp(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def provider_cooldown_active(name: str, *, now: datetime | None = None) -> bool:
    current = _as_utc(now)
    try:
        with _locked_state(current) as (_, payload):
            entry = payload.get("providers", {}).get(str(name), {})
            cooldown_until = _parse_timestamp(entry.get("cooldown_until"))
            return bool(cooldown_until and cooldown_until > current)
    except OSError as exc:
        logger.warning("LLM reliability state could not be read: %s", exc)
        return False


def _provider_public(entry: dict[str, Any], now: datetime) -> dict[str, Any]:
    attempts = _nonnegative_int(entry.get("attempts", 0))
    successes = _nonnegative_int(entry.get("successes", 0))
    failures = _nonnegative_int(entry.get("failures", 0))
    cooldown_until = _parse_timestamp(entry.get("cooldown_until"))
    if cooldown_until and cooldown_until > now:
        status = "cooling_down"
    elif attempts >= 10 and (successes / attempts) < 0.7:
        status = "degraded"
    elif successes:
        status = "healthy"
    elif failures:
        status = "degraded"
    else:
        status = "unknown"
    return {
        "status": status,
        "attempts": attempts,
        "successes": successes,
        "failures": failures,
        "success_rate_pct": round((successes / attempts) * 100, 1) if attempts else None,
        "rate_limits": _nonnegative_int(entry.get("rate_limits", 0)),
        "empty_responses": _nonnegative_int(entry.get("empty_responses", 0)),
        "consecutive_failures": _nonnegative_int(entry.get("consecutive_failures", 0)),
        "cooldown_until": cooldown_until.isoformat() if cooldown_until else None,
        "last_success": entry.get("last_success"),
        "last_failure": entry.get("last_failure"),
    }


def get_llm_reliability(
    *,
    now: datetime | None = None,
    state_file: Path | None = None,
) -> dict[str, Any]:
    current = _as_utc(now)
    try:
        with _locked_state(current, state_file) as (_, payload):
            requests = payload.get("requests", {})
            total = _nonnegative_int(requests.get("total", 0))
            successful = _nonnegative_int(requests.get("successful", 0))
            failed = _nonnegative_int(requests.get("failed", 0))
            success_rate = round((successful / total) * 100, 1) if total else None
            status = (
                "degraded"
                if total >= 10 and success_rate is not None and success_rate < 90
                else "healthy" if total else "unknown"
            )
            providers = {
                str(name): _provider_public(entry, current)
                for name, entry in payload.get("providers", {}).items()
                if isinstance(entry, dict)
            }
    except OSError as exc:
        logger.warning("LLM reliability state could not be read: %s", exc)
        return {
            "status": "unknown",
            "day": current.date().isoformat(),
            "requests": {"total": 0, "successful": 0, "failed": 0, "success_rate_pct": None},
            "providers": {},
            "generated_at": current.isoformat(),
        }
    return {
        "status": status,
        "day": payload.get("day"),
        "requests": {
            "total": total,
            "successful": successful,
            "failed": failed,
            "success_rate_pct": success_rate,
        },
        "providers": providers,
        "generated_at": current.isoformat(),
    }
