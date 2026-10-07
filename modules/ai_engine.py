import json
import re
import logging
import hashlib
from typing import Any

logger = logging.getLogger(__name__)

from modules.config import (
    SYSTEM_PROMPT,
    MAX_CONTENT_CHARS,
)
from modules.ai_cache import get_cached_result, cache_result
from modules.cost_tracker import check_daily_budget

_client = None
_failure_count = 0
_budget_skip_count = 0

SAFE_DEFAULT = {
    "is_cyber_attack": False,
    "category": "General Cyber Threat",
    "confidence": 0,
    "translated_title": "",
    "summary": "",
}


from modules.utils import extract_json as _extract_json


def analyze_article(title: str, content: str | None = None, source_language: str = "en") -> dict[str, Any]:
    from modules.llm_client import call_llm

    try:
        cache_key = None
        if content:
            cache_key = compute_content_hash(title + content)
        else:
            cache_key = compute_content_hash(title)

        cached = get_cached_result(cache_key)
        if cached is not None:
            cached["_cached"] = True
            return cached

        user_content = f"Headline: {title}\nSource language: {source_language}"
        if content:
            truncated = content[:MAX_CONTENT_CHARS]
            user_content += f"\n\nArticle content:\n{truncated}"

        if not check_daily_budget():
            global _budget_skip_count
            _budget_skip_count += 1
            logger.warning(f"Budget limit reached, skipping: {title}")
            return {**SAFE_DEFAULT, "translated_title": title, "_budget_skipped": True}

        reply = call_llm(
            user_content,
            system_prompt=SYSTEM_PROMPT,
            max_tokens=500,
            caller="ai_engine",
        )
        result = _extract_json(reply)

        if result is None:
            logger.warning(f"Failed to parse AI response for: {title}")
            return {**SAFE_DEFAULT, "translated_title": title, "ai_analysis_failed": True}

        for key in SAFE_DEFAULT:
            if key not in result:
                result[key] = SAFE_DEFAULT[key]

        if not result["translated_title"]:
            result["translated_title"] = title

        cache_result(cache_key, result)
        return result

    except Exception as e:
        global _failure_count
        _failure_count += 1
        logger.error(f"Unexpected error analyzing '{title}': {e}")
        return {**SAFE_DEFAULT, "translated_title": title, "ai_analysis_failed": True}


def get_failure_stats() -> dict[str, int]:
    return {
        "failures": _failure_count,
        "budget_skips": _budget_skip_count,
    }


def compute_content_hash(content: str) -> str:
    return hashlib.sha256(content[:MAX_CONTENT_CHARS].encode()).hexdigest()
