"""Freshness and generation status for Hunts and Threat Ledger artifacts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.config import OUTPUT_DIR, STATE_DIR
from modules.utils import write_json_atomic

_ARTIFACTS = {
    "incidents": ("incidents-v2.json", "records"),
    "hunts": ("hunts.json", "hunts"),
    "ledger": ("threat_ledger.json", "records"),
}


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)


def _status(path: Path, collection: str, max_age_hours: float) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"ok": False, "stale": True, "age_hours": None, "reason": "missing"}
    except (OSError, json.JSONDecodeError):
        return {"ok": False, "stale": True, "age_hours": None, "reason": "invalid"}
    if not isinstance(payload, dict) or not isinstance(payload.get(collection), list):
        return {"ok": False, "stale": True, "age_hours": None, "reason": "invalid_shape"}
    generated_at = _timestamp(payload.get("generated_at"))
    if generated_at is None:
        return {"ok": False, "stale": True, "age_hours": None, "reason": "timestamp_missing"}
    age = max(0.0, (datetime.now(timezone.utc) - generated_at).total_seconds() / 3600)
    stale = age > max_age_hours
    return {
        "ok": not stale,
        "stale": stale,
        "age_hours": round(age, 2),
        "generated_at": generated_at.isoformat(),
        "reason": "stale" if stale else "fresh",
    }


def check_operational_artifact_health(
    output_dir: Path = OUTPUT_DIR,
    max_age_hours: float = 1.0,
) -> dict[str, Any]:
    configured = (output_dir / "daily_latest.json").exists() or any(
        (output_dir / filename).exists() for filename, _ in _ARTIFACTS.values()
    )
    capabilities = {
        name: _status(output_dir / filename, collection, max_age_hours)
        for name, (filename, collection) in _ARTIFACTS.items()
    }
    stale = [name for name, status in capabilities.items() if not status["ok"]]
    failing: list[str] = []
    state_path = output_dir.parent / "state" / "operational_artifact_health.json"
    try:
        run_status = json.loads(state_path.read_text(encoding="utf-8"))
        checked_at = _timestamp(run_status.get("generated_at"))
        recent = checked_at and (
            datetime.now(timezone.utc) - checked_at
        ).total_seconds() <= 3 * 3600
        if recent:
            failing = [
                name for name, status in run_status.get("capabilities", {}).items()
                if isinstance(status, dict) and not status.get("ok", False)
            ]
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    return {
        "configured": configured,
        "ok": configured and not stale and not failing,
        "stale_capabilities": stale,
        "failing_capabilities": failing,
        "capabilities": capabilities,
    }


def write_operational_artifact_status(
    capabilities: dict[str, dict[str, Any]],
    state_dir: Path = STATE_DIR,
) -> None:
    write_json_atomic(
        state_dir / "operational_artifact_health.json",
        {"generated_at": datetime.now(timezone.utc).isoformat(), "capabilities": capabilities},
        indent=2,
        ensure_ascii=False,
    )
