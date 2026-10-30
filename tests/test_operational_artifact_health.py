"""Health checks for hunt and ledger artifacts."""

import json
from datetime import datetime, timedelta, timezone

from modules.operational_artifact_health import check_operational_artifact_health


def _write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_fresh_valid_hunt_and_ledger_artifacts_are_healthy(tmp_path):
    output = tmp_path / "output"
    now = datetime.now(timezone.utc).isoformat()
    _write(output / "daily_latest.json", [])
    _write(output / "incidents-v2.json", {"generated_at": now, "records": []})
    _write(output / "hunts.json", {"generated_at": now, "hunts": []})
    _write(output / "threat_ledger.json", {"generated_at": now, "records": []})

    result = check_operational_artifact_health(output)

    assert result["configured"] is True
    assert result["ok"] is True
    assert result["failing_capabilities"] == []


def test_recent_generation_failure_degrades_even_with_fresh_artifact(tmp_path):
    output = tmp_path / "output"
    now = datetime.now(timezone.utc).isoformat()
    _write(output / "daily_latest.json", [])
    _write(output / "incidents-v2.json", {"generated_at": now, "records": []})
    _write(output / "hunts.json", {"generated_at": now, "hunts": []})
    _write(output / "threat_ledger.json", {"generated_at": now, "records": []})
    _write(tmp_path / "state" / "operational_artifact_health.json", {
        "generated_at": now,
        "capabilities": {
            "incidents": {"ok": True},
            "hunts": {"ok": False, "error": "generation_failed"},
            "ledger": {"ok": True},
        },
    })

    result = check_operational_artifact_health(output)

    assert result["ok"] is False
    assert result["failing_capabilities"] == ["hunts"]


def test_stale_ledger_is_reported(tmp_path):
    output = tmp_path / "output"
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    now = datetime.now(timezone.utc).isoformat()
    _write(output / "daily_latest.json", [])
    _write(output / "incidents-v2.json", {"generated_at": now, "records": []})
    _write(output / "hunts.json", {"generated_at": now, "hunts": []})
    _write(output / "threat_ledger.json", {"generated_at": old, "records": []})

    result = check_operational_artifact_health(output, max_age_hours=1)

    assert result["ok"] is False
    assert result["stale_capabilities"] == ["ledger"]
