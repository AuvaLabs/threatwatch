"""Transparent evidence measurements for public incident records."""

from __future__ import annotations

from collections import Counter
from typing import Any


def _items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def assess_incident_evidence(
    sources: list[dict[str, Any]], claims: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Attach citation measurements to claims and summarize record evidence."""
    source_by_id = {
        str(source.get("article_id")): source
        for source in _items(sources)
        if source.get("article_id")
    }
    enriched = [_assess_claim(claim, source_by_id) for claim in _items(claims)]
    cited = sum(bool(claim["evidence"]["source_count"]) for claim in enriched)
    state_counts = Counter(str(claim.get("state") or "unknown") for claim in enriched)
    independent = len({
        str(source.get("source_family"))
        for source in source_by_id.values()
        if source.get("source_family")
    })
    authoritative = sum(source.get("role") == "authoritative" for source in source_by_id.values())
    coverage = round(cited / len(enriched) * 100) if enriched else 100
    disputed = state_counts["disputed"]
    grade = _grade(coverage, independent, disputed)
    assessment = {
        "grade": grade,
        "citation_coverage_pct": coverage,
        "claim_count": len(enriched),
        "cited_claim_count": cited,
        "independent_source_count": independent,
        "authoritative_source_count": authoritative,
        "confirmed_claim_count": state_counts["confirmed"],
        "reported_claim_count": state_counts["reported"],
        "assessed_claim_count": state_counts["assessed"],
        "disputed_claim_count": disputed,
        "basis": _basis(independent, coverage, authoritative, disputed),
    }
    return enriched, assessment


def _assess_claim(
    claim: dict[str, Any], source_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    retained = [
        source_by_id[str(source_id)]
        for source_id in claim.get("source_ids", [])
        if str(source_id) in source_by_id
    ]
    families = {str(source.get("source_family")) for source in retained if source.get("source_family")}
    evidence = {
        "source_count": len(retained),
        "independent_source_count": len(families),
        "authoritative_source_count": sum(source.get("role") == "authoritative" for source in retained),
    }
    return {**claim, "evidence": evidence}


def _grade(coverage: int, independent: int, disputed: int) -> str:
    if coverage < 100:
        return "insufficient"
    if independent >= 2 and disputed:
        return "mixed"
    if independent >= 2:
        return "corroborated"
    return "developing"


def _basis(independent: int, coverage: int, authoritative: int, disputed: int) -> list[str]:
    family_label = "family" if independent == 1 else "families"
    authority = (
        f"{authoritative} source{'s are' if authoritative != 1 else ' is'} marked authoritative"
        if authoritative else "No source is marked authoritative"
    )
    claims = (
        "All claims are linked to retained evidence"
        if coverage == 100 else f"{coverage}% of claims are linked to retained evidence"
    )
    result = [f"{independent} independent source {family_label}", claims, authority]
    if disputed:
        result.append(f"{disputed} disputed claim{'s' if disputed != 1 else ''} retained")
    return result
