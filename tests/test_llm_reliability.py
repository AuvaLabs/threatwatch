from datetime import datetime, timedelta, timezone
import json

from modules import llm_reliability


def _state_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(
        llm_reliability, "STATE_FILE", tmp_path / "llm_reliability.json",
    )
    monkeypatch.setattr(
        llm_reliability, "LOCK_FILE", tmp_path / "llm_reliability.lock",
    )


def test_provider_cooldown_persists_across_calls(monkeypatch, tmp_path):
    _state_paths(monkeypatch, tmp_path)
    now = datetime(2026, 11, 21, 6, 0, tzinfo=timezone.utc)

    llm_reliability.record_provider_failure(
        "primary", "rate_limit", threshold=1, cooldown_seconds=3600, now=now,
    )

    assert llm_reliability.provider_cooldown_active("primary", now=now)
    assert not llm_reliability.provider_cooldown_active(
        "primary", now=now + timedelta(hours=1, seconds=1),
    )


def test_empty_responses_are_counted_and_cooled(monkeypatch, tmp_path):
    _state_paths(monkeypatch, tmp_path)
    now = datetime(2026, 11, 21, 6, 0, tzinfo=timezone.utc)

    llm_reliability.record_provider_failure(
        "anthropic", "empty_response", threshold=2,
        cooldown_seconds=3600, now=now,
    )
    llm_reliability.record_provider_failure(
        "anthropic", "empty_response", threshold=2,
        cooldown_seconds=3600, now=now,
    )
    health = llm_reliability.get_llm_reliability(now=now)

    assert health["providers"]["anthropic"]["empty_responses"] == 2
    assert health["providers"]["anthropic"]["status"] == "cooling_down"


def test_success_resets_consecutive_failures(monkeypatch, tmp_path):
    _state_paths(monkeypatch, tmp_path)
    now = datetime(2026, 11, 21, 6, 0, tzinfo=timezone.utc)
    llm_reliability.record_provider_failure(
        "primary", "rate_limit", threshold=3, cooldown_seconds=3600, now=now,
    )

    llm_reliability.record_provider_success("primary", now=now)
    health = llm_reliability.get_llm_reliability(now=now)

    assert health["providers"]["primary"]["consecutive_failures"] == 0
    assert health["providers"]["primary"]["successes"] == 1
    assert not llm_reliability.provider_cooldown_active("primary", now=now)


def test_request_success_rate_is_public_and_bounded(monkeypatch, tmp_path):
    _state_paths(monkeypatch, tmp_path)
    now = datetime(2026, 11, 21, 6, 0, tzinfo=timezone.utc)
    for _ in range(9):
        llm_reliability.record_request_result(True, "classify", now=now)
    llm_reliability.record_request_result(False, "classify", now=now)

    health = llm_reliability.get_llm_reliability(now=now)

    assert health["status"] == "healthy"
    assert health["requests"] == {
        "total": 10,
        "successful": 9,
        "failed": 1,
        "success_rate_pct": 90.0,
    }
    assert "caller" not in str(health)


def test_low_request_success_rate_is_degraded(monkeypatch, tmp_path):
    _state_paths(monkeypatch, tmp_path)
    now = datetime(2026, 11, 21, 6, 0, tzinfo=timezone.utc)
    for success in [True] * 8 + [False] * 2:
        llm_reliability.record_request_result(success, "summaries", now=now)

    assert llm_reliability.get_llm_reliability(now=now)["status"] == "degraded"


def test_malformed_counter_values_fail_open(monkeypatch, tmp_path):
    _state_paths(monkeypatch, tmp_path)
    now = datetime(2026, 11, 21, 6, 0, tzinfo=timezone.utc)
    llm_reliability.STATE_FILE.write_text(json.dumps({
        "schema_version": 1,
        "day": "2026-11-21",
        "requests": {"total": None, "successful": "bad", "failed": -4},
        "providers": {
            "primary": {
                "attempts": None,
                "successes": "bad",
                "failures": -2,
                "consecutive_failures": None,
            },
        },
    }))

    health = llm_reliability.get_llm_reliability(now=now)

    assert health["status"] == "unknown"
    assert health["requests"]["total"] == 0
    assert health["providers"]["primary"]["attempts"] == 0


def test_daily_counters_reset_without_dropping_active_cooldown(monkeypatch, tmp_path):
    _state_paths(monkeypatch, tmp_path)
    before_midnight = datetime(2026, 11, 21, 23, 59, tzinfo=timezone.utc)
    after_midnight = before_midnight + timedelta(minutes=2)
    llm_reliability.record_provider_failure(
        "primary",
        "rate_limit",
        threshold=1,
        cooldown_seconds=3600,
        now=before_midnight,
    )

    health = llm_reliability.get_llm_reliability(now=after_midnight)

    assert health["day"] == "2026-11-22"
    assert health["providers"]["primary"]["attempts"] == 0
    assert health["providers"]["primary"]["status"] == "cooling_down"
    assert llm_reliability.provider_cooldown_active(
        "primary", now=after_midnight,
    )
