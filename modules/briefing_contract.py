"""Shared validation for publishable, source-grounded briefings."""

from __future__ import annotations

from typing import Any


def briefing_validation_reason(briefing: object) -> str | None:
    """Return why a briefing cannot be published, or None when it can."""
    if not isinstance(briefing, dict):
        return "invalid_shape"
    if not str(briefing.get("headline") or "").strip():
        return "headline_missing"
    if not str(briefing.get("what_happened") or "").strip():
        return "assessment_missing"
    sources = briefing.get("source_articles")
    if not isinstance(sources, list) or not sources:
        return "sources_missing"
    has_linked_source = any(
        isinstance(source, dict)
        and str(source.get("link") or "").startswith(("https://", "http://"))
        for source in sources
    )
    return None if has_linked_source else "source_links_missing"


def is_grounded_briefing(briefing: object) -> bool:
    """Return whether a briefing meets the public delivery contract."""
    return briefing_validation_reason(briefing) is None
