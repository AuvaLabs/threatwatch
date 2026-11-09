import pytest

from modules.release_health import require_deployable_health


def test_accepts_healthy_release_state():
    require_deployable_health({"status": "ok", "reasons": []})


def test_accepts_only_expected_budget_limited_state():
    require_deployable_health({
        "status": "degraded",
        "reasons": ["llm_budget_exceeded_last_run"],
    })


@pytest.mark.parametrize("payload", [
    {"status": "degraded", "reasons": ["pipeline_stale"]},
    {"status": "degraded", "reasons": ["llm_budget_exceeded_last_run", "backup_stale"]},
    {"status": "degraded", "reasons": []},
    {"status": "down", "reasons": []},
])
def test_rejects_every_other_degradation(payload):
    with pytest.raises(ValueError):
        require_deployable_health(payload)
