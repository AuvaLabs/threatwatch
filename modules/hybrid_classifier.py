"""Hybrid classifier: keyword-first, AI-escalation for ambiguous articles.

Runs the zero-cost keyword classifier on every article. If the result
is low-confidence or falls into a catch-all category, escalates to the
AI engine for a better classification and summary. Falls back to the
keyword result if the AI call fails or the budget is exhausted.

When ANTHROPIC_API_KEY is not set, behaves identically to the keyword
classifier (zero cost, no API calls).
"""

import logging

from modules.config import ANTHROPIC_API_KEY
from modules.keyword_classifier import classify_article as keyword_classify

logger = logging.getLogger(__name__)

# Threshold below which we escalate to AI
AI_ESCALATION_CONFIDENCE = 70

# Categories that always escalate (too vague for regex alone)
AI_ESCALATION_CATEGORIES = frozenset({
    "General Cyber Threat",
})


def _should_escalate(keyword_result):
    """Decide whether an article needs AI classification."""
    if not ANTHROPIC_API_KEY:
        return False

    if not keyword_result.get("is_cyber_attack"):
        return False

    category = keyword_result.get("category", "")
    confidence = keyword_result.get("confidence", 0)

    if category in AI_ESCALATION_CATEGORIES:
        return True

    if confidence < AI_ESCALATION_CONFIDENCE:
        return True

    return False


def classify_article(title, content=None, source_language="en"):
    """Classify an article using keyword-first, AI-escalation hybrid.

    Returns the same dict structure as both keyword_classifier and
    ai_engine for full compatibility.
    """
    # Step 1: keyword classifier (always runs, zero cost)
    keyword_result = keyword_classify(title, content, source_language)

    # Step 2: decide whether to escalate
    if not _should_escalate(keyword_result):
        return keyword_result

    # Step 3: call AI engine (lazy import to avoid loading anthropic when unused)
    try:
        from modules.ai_engine import analyze_article as ai_classify

        logger.info(
            "AI escalation: '%s' (keyword: %s @ %d%%)",
            title[:60],
            keyword_result.get("category"),
            keyword_result.get("confidence", 0),
        )

        ai_result = ai_classify(title, content, source_language)

        # If AI failed or was budget-skipped, keep keyword result
        if ai_result.get("ai_analysis_failed") or ai_result.get("_budget_skipped"):
            logger.debug("AI unavailable, keeping keyword result for: %s", title[:60])
            return keyword_result

        # Tag the result so callers know AI was used
        ai_result["_ai_enhanced"] = True
        ai_result["_keyword_category"] = keyword_result.get("category")
        ai_result["_keyword_confidence"] = keyword_result.get("confidence", 0)

        return ai_result

    except Exception as e:
        logger.warning("AI escalation failed for '%s': %s", title[:60], e)
        return keyword_result
