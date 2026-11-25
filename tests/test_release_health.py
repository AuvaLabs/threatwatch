import pytest

from modules.release_health import require_deployable_health


def test_accepts_healthy_release_state():
    require_deployable_health({"status": "ok", "reasons": []})


def test_accepts_only_expected_budget_limited_state():
    require_deployable_health({
        "status": "degraded",
        "reasons": ["llm_budget_exceeded_last_run"],
    })


def test_accepts_legacy_small_sample_analysis_degradation():
    require_deployable_health({
        "status": "degraded",
        "reasons": ["analysis_failure_rate_1/2"],
        "articles_enriched": 2,
        "analysis_failures": 1,
    })


def test_accepts_stale_command_edition_when_live_fallback_is_fresh():
    require_deployable_health({
        "status": "degraded",
        "reasons": ["artifact_stale_command_brief"],
        "ai_artifacts": {
            "capabilities": {
                "global_briefing": {"ok": True, "stale": False},
                "command_brief": {"ok": False, "stale": True},
            },
        },
    })


def test_accepts_failed_refresh_attempts_when_published_artifacts_are_fresh():
    require_deployable_health({
        "status": "degraded",
        "reasons": [
            "ai_capability_failing_regional_briefings",
            "ai_capability_failing_top_stories",
        ],
        "ai_artifacts": {
            "capabilities": {
                "regional_na": {"ok": True, "stale": False},
                "regional_emea": {"ok": True, "stale": False},
                "regional_apac": {"ok": True, "stale": False},
                "top_stories": {"ok": True, "stale": False},
            },
        },
    })


def test_rejects_failed_refresh_attempt_when_published_artifact_is_stale():
    payload = {
        "status": "degraded",
        "reasons": ["ai_capability_failing_regional_briefings"],
        "ai_artifacts": {
            "capabilities": {
                "regional_na": {"ok": True, "stale": False},
                "regional_emea": {"ok": False, "stale": True},
                "regional_apac": {"ok": True, "stale": False},
            },
        },
    }

    with pytest.raises(ValueError):
        require_deployable_health(payload)


def test_enrichment_repair_can_release_with_fresh_delivery_and_pipeline():
    payload = {
        "status": "degraded",
        "reasons": ["llm_reliability_degraded"],
        "last_run_age_s": 500,
        "heartbeat_age_s": 20,
        "analysis_failures": 0,
        "ai_artifacts": {"ok": True},
        "operational_artifacts": {"ok": True},
    }
    with pytest.raises(ValueError):
        require_deployable_health(payload)
    require_deployable_health(payload, repair_enrichment=True)
    require_deployable_health(
        {**payload, "analysis_failures": 1, "articles_enriched": 2},
        repair_enrichment=True,
    )

    for unhealthy in (
        {"ai_artifacts": {"ok": False}},
        {"operational_artifacts": {"ok": False}},
        {"last_run_age_s": 901},
        {"heartbeat_age_s": None},
        {"analysis_failures": 4},
        {"analysis_failures": 4, "articles_enriched": 10},
        {"reasons": ["llm_reliability_degraded", "pipeline_stale"]},
    ):
        with pytest.raises(ValueError):
            require_deployable_health({**payload, **unhealthy}, repair_enrichment=True)


@pytest.mark.parametrize("global_briefing", [
    None,
    {},
    {"ok": False, "stale": False},
    {"ok": True, "stale": True},
])
def test_rejects_stale_command_edition_without_fresh_live_fallback(
    global_briefing,
):
    payload = {
        "status": "degraded",
        "reasons": ["artifact_stale_command_brief"],
        "ai_artifacts": {"capabilities": {}},
    }
    if global_briefing is not None:
        payload["ai_artifacts"]["capabilities"]["global_briefing"] = global_briefing

    with pytest.raises(ValueError):
        require_deployable_health(payload)


@pytest.mark.parametrize("payload", [
    {"status": "degraded", "reasons": ["pipeline_stale"]},
    {"status": "degraded", "reasons": ["llm_budget_exceeded_last_run", "backup_stale"]},
    {"status": "degraded", "reasons": ["analysis_failure_rate_3/10"], "articles_enriched": 10, "analysis_failures": 3},
    {"status": "degraded", "reasons": []},
    {"status": "down", "reasons": []},
])
def test_rejects_every_other_degradation(payload):
    with pytest.raises(ValueError):
        require_deployable_health(payload)
