"""Release-specific interpretation of public platform health."""

from __future__ import annotations

from typing import Any


ALLOWED_RELEASE_DEGRADATIONS = frozenset({"llm_budget_exceeded_last_run"})


def require_deployable_health(payload: dict[str, Any]) -> None:
    """Raise unless health is safe for deployment and automatic rollback."""
    status = payload.get("status")
    if status == "ok":
        return
    reasons = payload.get("reasons")
    reason_set = set(reasons) if isinstance(reasons, list) else set()
    budget_limited = (
        status == "degraded"
        and bool(reason_set)
        and reason_set <= ALLOWED_RELEASE_DEGRADATIONS
    )
    if not budget_limited:
        raise ValueError(f"health is not deployable: status={status!r}, reasons={sorted(reason_set)!r}")
