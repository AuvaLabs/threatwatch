"""Hybrid classifier: keyword-first, AI-escalation for ambiguous articles.

Runs the zero-cost keyword classifier on every article. If the result
is low-confidence or falls into a catch-all category, escalates to the
AI engine (Groq or Anthropic) for a better classification and summary.
Falls back to the keyword result if the AI call fails.

Uses Groq (via llm_client) by default. Falls back to Anthropic SDK
if ANTHROPIC_API_KEY is set and Groq is not available.
"""

import logging
import hashlib

from modules.config import ANTHROPIC_API_KEY, SYSTEM_PROMPT, MAX_CONTENT_CHARS
from modules.keyword_classifier import classify_article as keyword_classify
from modules.ai_cache import get_cached_result, cache_result

logger = logging.getLogger(__name__)

# Threshold below which we escalate to AI
AI_ESCALATION_CONFIDENCE = 70

# Categories that always escalate (too vague for regex alone)
AI_ESCALATION_CATEGORIES = frozenset({
    "General Cyber Threat",
})

# Cap AI escalations per pipeline run to control token usage
_MAX_ESCALATIONS_PER_RUN = 20
_escalation_count = 0


def _should_escalate(keyword_result):
    """Decide whether an article needs AI classification."""
    from modules.llm_client import is_available as groq_available

    if not groq_available() and not ANTHROPIC_API_KEY:
        return False

    global _escalation_count
    if _escalation_count >= _MAX_ESCALATIONS_PER_RUN:
        return False

    if not keyword_result.get("is_cyber_attack"):
        return False

    category = keyword_result.get("category", "")
    confidence = keyword_result.get("confidence", 0)

    if category in AI_ESCALATION_CATEGORIES and confidence <= 60:
        return True

    if confidence < AI_ESCALATION_CONFIDENCE:
        return True

    return False


def _classify_via_groq(title, content=None):
    """Classify using Groq/OpenAI-compatible API via shared llm_client."""
    from modules.llm_client import call_llm
    from modules.utils import extract_json

    user_content = title
    if content:
        user_content += "\n\n" + content[:MAX_CONTENT_CHARS]

    # Check cache first
    cache_key = hashlib.sha256(
        ("classify:" + user_content).encode()
    ).hexdigest()
    cached = get_cached_result(cache_key)
    if cached is not None:
        cached["_cached"] = True
        return cached

    reply = call_llm(user_content, system_prompt=SYSTEM_PROMPT, max_tokens=300)
    result = extract_json(reply)
    if result and "is_cyber_attack" in result:
        cache_result(cache_key, result)
        return result
    return None


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

    global _escalation_count

    # Step 3: try Groq first (cheaper, faster), then Anthropic
    try:
        from modules.llm_client import is_available as groq_available

        if groq_available():
            logger.info(
                "AI escalation (Groq): '%s' (keyword: %s @ %d%%)",
                title[:60],
                keyword_result.get("category"),
                keyword_result.get("confidence", 0),
            )
            ai_result = _classify_via_groq(title, content)
            if ai_result and not ai_result.get("_cached"):
                _escalation_count += 1

            if ai_result:
                ai_result["_ai_enhanced"] = True
                ai_result["_keyword_category"] = keyword_result.get("category")
                ai_result["_keyword_confidence"] = keyword_result.get("confidence", 0)
                return ai_result

        # Fallback: Anthropic SDK
        if ANTHROPIC_API_KEY:
            from modules.ai_engine import analyze_article as ai_classify

            logger.info("AI escalation (Anthropic): '%s'", title[:60])
            ai_result = ai_classify(title, content, source_language)

            if ai_result.get("ai_analysis_failed") or ai_result.get("_budget_skipped"):
                return keyword_result

            _escalation_count += 1
            ai_result["_ai_enhanced"] = True
            ai_result["_keyword_category"] = keyword_result.get("category")
            ai_result["_keyword_confidence"] = keyword_result.get("confidence", 0)
            return ai_result

    except Exception as e:
        logger.warning("AI escalation failed for '%s': %s", title[:60], e)

    return keyword_result
