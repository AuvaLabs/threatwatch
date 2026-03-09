import json
import re
import logging
import hashlib
import time

import httpx
import anthropic

from modules.config import (
    ANTHROPIC_API_KEY,
    ANTHROPIC_MODEL,
    SYSTEM_PROMPT,
    MAX_CONTENT_CHARS,
)
from modules.ai_cache import get_cached_result, cache_result
from modules.cost_tracker import track_usage, check_daily_budget

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


def _get_client():
    global _client
    if _client is None:
        _client = anthropic.Anthropic(
            api_key=ANTHROPIC_API_KEY,
            timeout=httpx.Timeout(60.0, connect=15.0),
            max_retries=2,
        )
    return _client


def _extract_json(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None


def analyze_article(title, content=None, source_language="en"):
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
            logging.warning(f"Budget limit reached, skipping: {title}")
            return {**SAFE_DEFAULT, "translated_title": title, "_budget_skipped": True}

        client = _get_client()
        response = None
        for attempt in range(3):
            try:
                response = client.messages.create(
                    model=ANTHROPIC_MODEL,
                    max_tokens=500,
                    system=[
                        {
                            "type": "text",
                            "text": SYSTEM_PROMPT,
                            "cache_control": {"type": "ephemeral"},
                        }
                    ],
                    messages=[{"role": "user", "content": user_content}],
                    temperature=0.2,
                )
                break
            except (anthropic.APIConnectionError, anthropic.APITimeoutError, anthropic.InternalServerError) as e:
                logging.warning(f"API attempt {attempt + 1}/3 failed for '{title[:50]}': {e}")
                if attempt < 2:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise

        track_usage(response)
        reply_text = response.content[0].text.strip()
        result = _extract_json(reply_text)

        if result is None:
            logging.warning(f"Failed to parse AI response for: {title}")
            return {**SAFE_DEFAULT, "translated_title": title}

        for key in SAFE_DEFAULT:
            if key not in result:
                result[key] = SAFE_DEFAULT[key]

        if not result["translated_title"]:
            result["translated_title"] = title

        cache_result(cache_key, result)
        return result

    except anthropic.APIError as e:
        global _failure_count
        _failure_count += 1
        logging.error(f"Anthropic API error for '{title}': {e}")
        return {**SAFE_DEFAULT, "translated_title": title, "ai_analysis_failed": True}
    except Exception as e:
        _failure_count += 1
        logging.error(f"Unexpected error analyzing '{title}': {e}")
        return {**SAFE_DEFAULT, "translated_title": title, "ai_analysis_failed": True}


def get_failure_stats():
    return {
        "failures": _failure_count,
        "budget_skips": _budget_skip_count,
    }


def compute_content_hash(content):
    return hashlib.sha256(content[:MAX_CONTENT_CHARS].encode()).hexdigest()
