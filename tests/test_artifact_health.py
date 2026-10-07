"""Freshness checks for analyst-facing generated artifacts."""

import json
from datetime import datetime, timedelta, timezone

from modules.artifact_health import check_artifact_health


def _write(path, generated_at):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": generated_at}), encoding="utf-8")


def test_stale_top_stories_degrades_artifact_health(tmp_path):
    output = tmp_path / "output"
    now = datetime.now(timezone.utc)
    fresh = now.isoformat()
    stale = (now - timedelta(days=2)).isoformat()
    _write(output / "briefing.json", fresh)
    _write(output / "top_stories.json", stale)
    for region in ("na", "emea", "apac"):
        _write(output / f"briefing_{region}.json", fresh)

    result = check_artifact_health(output)

    assert result["configured"] is True
    assert result["ok"] is False
    assert result["capabilities"]["top_stories"]["stale"] is True


def test_all_fresh_artifacts_are_healthy(tmp_path):
    output = tmp_path / "output"
    fresh = datetime.now(timezone.utc).isoformat()
    for name in ("briefing.json", "top_stories.json", "briefing_na.json",
                 "briefing_emea.json", "briefing_apac.json"):
        _write(output / name, fresh)

    result = check_artifact_health(output)

    assert result["ok"] is True
    assert result["stale_capabilities"] == []


def test_missing_sibling_artifact_is_unhealthy_when_ai_is_configured(tmp_path):
    output = tmp_path / "output"
    _write(output / "briefing.json", datetime.now(timezone.utc).isoformat())

    result = check_artifact_health(output)

    assert result["ok"] is False
    assert result["capabilities"]["top_stories"]["reason"] == "missing"


def test_recent_capability_failure_is_reported(tmp_path):
    output = tmp_path / "output"
    fresh = datetime.now(timezone.utc).isoformat()
    for name in ("briefing.json", "top_stories.json", "briefing_na.json",
                 "briefing_emea.json", "briefing_apac.json"):
        _write(output / name, fresh)
    state = tmp_path / "state"
    state.mkdir()
    (state / "ai_health.json").write_text(json.dumps({
        "generated_at": fresh,
        "capabilities": {
            "top_stories": {"ok": False, "error": "generation_failed"},
            "global_briefing": {"ok": True},
        },
    }))

    result = check_artifact_health(output)

    assert result["ok"] is False
    assert result["failing_capabilities"] == ["top_stories"]
