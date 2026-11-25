"""Release-specific interpretation of public platform health."""

from __future__ import annotations

from typing import Any


ALLOWED_RELEASE_DEGRADATIONS = frozenset({"llm_budget_exceeded_last_run"})
MIN_ANALYSIS_SAMPLE = 10
_ENRICHMENT_REPAIR_MAX_PIPELINE_AGE_S = 900
_REFRESH_ARTIFACTS = {
    "ai_capability_failing_global_briefing": ("global_briefing",),
    "ai_capability_failing_regional_briefings": (
        "regional_na", "regional_emea", "regional_apac",
    ),
    "ai_capability_failing_top_stories": ("top_stories",),
}


def _fresh_live_briefing(payload: dict[str, Any]) -> bool:
    artifacts = payload.get("ai_artifacts")
    capabilities = artifacts.get("capabilities") if isinstance(artifacts, dict) else None
    briefing = capabilities.get("global_briefing") if isinstance(capabilities, dict) else None
    return bool(
        isinstance(briefing, dict)
        and briefing.get("ok") is True
        and briefing.get("stale") is False
    )


def _artifacts_are_fresh(payload: dict[str, Any], names: tuple[str, ...]) -> bool:
    artifacts = payload.get("ai_artifacts")
    capabilities = artifacts.get("capabilities") if isinstance(artifacts, dict) else None
    if not isinstance(capabilities, dict):
        return False
    return all(
        isinstance(capabilities.get(name), dict)
        and capabilities[name].get("ok") is True
        and capabilities[name].get("stale") is False
        for name in names
    )


def _enrichment_repair_baseline(payload: dict[str, Any]) -> bool:
    ages = (payload.get("last_run_age_s"), payload.get("heartbeat_age_s"))
    artifacts = (payload.get("ai_artifacts"), payload.get("operational_artifacts"))
    enriched = payload.get("articles_enriched")
    failures = payload.get("analysis_failures")
    return (
        all(type(age) is int and 0 <= age <= _ENRICHMENT_REPAIR_MAX_PIPELINE_AGE_S for age in ages)
        and all(isinstance(group, dict) and group.get("ok") is True for group in artifacts)
        and (failures == 0 or _small_analysis_sample(enriched, failures))
    )


def _small_analysis_sample(enriched: object, failures: object) -> bool:
    return (
        isinstance(enriched, int)
        and isinstance(failures, int)
        and 0 < enriched < MIN_ANALYSIS_SAMPLE
        and 0 <= failures <= enriched
    )


def require_deployable_health(payload: dict[str, Any], *, repair_enrichment: bool = False) -> None:
    """Raise unless health is safe for deployment and automatic rollback."""
    status = payload.get("status")
    if status == "ok":
        return
    reasons = payload.get("reasons")
    reason_set = set(reasons) if isinstance(reasons, list) else set()
    if (
        repair_enrichment and status == "degraded"
        and reason_set == {"llm_reliability_degraded"}
        and _enrichment_repair_baseline(payload)
    ):
        return
    allowed_reasons = set(ALLOWED_RELEASE_DEGRADATIONS)
    enriched = payload.get("articles_enriched")
    failures = payload.get("analysis_failures")
    if _fresh_live_briefing(payload):
        allowed_reasons.add("artifact_stale_command_brief")
    for reason, artifact_names in _REFRESH_ARTIFACTS.items():
        if reason in reason_set and _artifacts_are_fresh(payload, artifact_names):
            allowed_reasons.add(reason)
    if _small_analysis_sample(enriched, failures):
        allowed_reasons.add(f"analysis_failure_rate_{failures}/{enriched}")
    safely_degraded = (
        status == "degraded"
        and bool(reason_set)
        and reason_set <= allowed_reasons
    )
    if not safely_degraded:
        raise ValueError(f"health is not deployable: status={status!r}, reasons={sorted(reason_set)!r}")
