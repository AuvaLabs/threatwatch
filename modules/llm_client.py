"""Shared LLM client with smart key rotation and 429 failover.

All AI features use this module to call Groq/OpenAI-compatible APIs.
Supports multiple API keys via LLM_API_KEYS env var (comma-separated).
"""

import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pathlib import Path

from modules.config import (
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_API_KEYS, OUTPUT_DIR,
)

logger = logging.getLogger(__name__)

_key_index_path = OUTPUT_DIR / ".llm_key_index"


def _next_api_key() -> str:
    """Return the next API key using smart rotation."""
    if len(LLM_API_KEYS) <= 1:
        return LLM_API_KEY
    try:
        idx = int(_key_index_path.read_text().strip()) if _key_index_path.exists() else 0
    except (ValueError, OSError):
        idx = 0
    key = LLM_API_KEYS[idx % len(LLM_API_KEYS)]
    try:
        _key_index_path.parent.mkdir(parents=True, exist_ok=True)
        _key_index_path.write_text(str((idx + 1) % len(LLM_API_KEYS)))
    except OSError:
        pass
    return key


def _advance_key() -> None:
    """Advance to next key (called on rate-limit)."""
    try:
        idx = int(_key_index_path.read_text().strip()) if _key_index_path.exists() else 0
        _key_index_path.write_text(str((idx + 1) % len(LLM_API_KEYS)))
    except (ValueError, OSError):
        pass


def _get_http_session() -> requests.Session:
    """Return a requests session with retry logic."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _response_format_unsupported(resp: requests.Response) -> bool:
    """Detect Groq/OpenAI errors that indicate `response_format` isn't supported.

    Returns True only if the status is 400 AND the response body mentions
    `response_format`. We intentionally keep the match narrow so unrelated 400s
    still bubble up as errors.
    """
    if resp.status_code != 400:
        return False
    try:
        body = (resp.text or "").lower()
    except Exception:
        return False
    return "response_format" in body


def call_llm(user_content: str, system_prompt: str,
             max_tokens: int = 2000,
             response_format: dict | None = None) -> str:
    """Call Groq/OpenAI-compatible API with smart key failover on 429s.

    Args:
        user_content: The user message content.
        system_prompt: The system prompt.
        max_tokens: Max tokens in the response.
        response_format: Optional OpenAI-style structured output hint, e.g.
            ``{"type": "json_object"}``. When supplied, the payload includes it
            and the model is forced to emit valid JSON. If the upstream API
            rejects the field with a 400 whose body mentions ``response_format``
            (e.g. a model/provider that doesn't support it), the same key is
            retried once without the field so callers degrade gracefully rather
            than breaking.

    Returns the raw text response from the LLM.
    Raises RuntimeError if all keys are exhausted.
    """
    url = f"{LLM_BASE_URL.rstrip('/')}/chat/completions"
    base_payload = {
        "model": LLM_MODEL,
        "max_tokens": max_tokens,
        "temperature": 0.3,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    }
    if response_format is not None:
        base_payload["response_format"] = response_format

    attempts = min(len(LLM_API_KEYS), 3) if len(LLM_API_KEYS) > 1 else 1
    last_error = None

    for attempt in range(attempts):
        api_key = _next_api_key()
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Each attempt may retry once without response_format if the provider
        # rejects the field. We copy so the retry doesn't mutate the base.
        payload = dict(base_payload)
        allow_response_format_fallback = response_format is not None

        while True:
            try:
                session = _get_http_session()
                resp = session.post(url, json=payload, headers=headers, timeout=90)
                if resp.status_code == 429:
                    logger.warning(f"Key {attempt + 1} rate-limited (429), trying next...")
                    _advance_key()
                    last_error = f"429 on key {attempt + 1}"
                    break  # break inner while → outer for picks next key
                if allow_response_format_fallback and _response_format_unsupported(resp):
                    logger.warning(
                        "LLM provider rejected response_format on key %d; "
                        "retrying same key without the field.",
                        attempt + 1,
                    )
                    payload = {k: v for k, v in payload.items() if k != "response_format"}
                    allow_response_format_fallback = False
                    continue  # retry same key, same payload minus response_format
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"].strip()
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 429:
                    logger.warning(f"Key {attempt + 1} rate-limited, trying next...")
                    _advance_key()
                    last_error = str(e)
                    break  # break inner while → outer for picks next key
                raise

    raise RuntimeError(f"All {attempts} API keys exhausted: {last_error}")


def is_available() -> bool:
    """Check if any LLM API key is configured."""
    return bool(LLM_API_KEY)
