"""Runtime policy for deferrable, routine LLM enrichment work."""

from __future__ import annotations

import os


ROUTINE_CALLERS = frozenset({
    "actor_profile",
    "ai_engine",
    "attack_llm",
    "classify",
    "cluster_synth",
    "cve_narrative",
    "ttp_extract",
})


def caller_enabled(caller: str | None) -> bool:
    if caller not in ROUTINE_CALLERS:
        return True
    return os.environ.get("ROUTINE_LLM_ENABLED", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }
