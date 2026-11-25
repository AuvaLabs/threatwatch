"""Release-specific interpretation of public platform health."""

from __future__ import annotations

from typing import Any


ALLOWED_RELEASE_DEGRADATIONS = frozenset({"llm_budget_exceeded_last_run"})
MIN_ANALYSIS_SAMPLE = 10


def _fresh_live_briefing(payload: dict[str, Any]) -> bool:
    artifacts = payload.get("ai_artifacts")
    capabilities = artifacts.get("capabilities") if isinstance(artifacts, dict) else None
    briefing = capabilities.get("global_briefing") if isinstance(capabilities, dict) else None
    return bool(
        isinstance(briefing, dict)
        and briefing.get("ok") is True
        and briefing.get("stale") is False
    )


def require_deployable_health(payload: dict[str, Any]) -> None:
    """Raise unless health is safe for deployment and automatic rollback."""
    status = payload.get("status")
    if status == "ok":
        return
    reasons = payload.get("reasons")
    reason_set = set(reasons) if isinstance(reasons, list) else set()
    allowed_reasons = set(ALLOWED_RELEASE_DEGRADATIONS)
    enriched = payload.get("articles_enriched")
    failures = payload.get("analysis_failures")
    if _fresh_live_briefing(payload):
        allowed_reasons.add("artifact_stale_command_brief")
    if (
        isinstance(enriched, int)
        and isinstance(failures, int)
        and 0 < enriched < MIN_ANALYSIS_SAMPLE
        and 0 <= failures <= enriched
    ):
        allowed_reasons.add(f"analysis_failure_rate_{failures}/{enriched}")
    safely_degraded = (
        status == "degraded"
        and bool(reason_set)
        and reason_set <= allowed_reasons
    )
    if not safely_degraded:
        raise ValueError(f"health is not deployable: status={status!r}, reasons={sorted(reason_set)!r}")
