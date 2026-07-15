"""Shared LLM client with smart key rotation and 429 failover.

All AI features use this module to call Groq/OpenAI-compatible APIs.
Supports multiple API keys via LLM_API_KEYS env var (comma-separated).
"""

import logging
import os
import requests
from pathlib import Path

from modules.config import (
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_API_KEYS, OUTPUT_DIR,
    FEATHERLESS_API_KEY, FEATHERLESS_BASE_URL, FEATHERLESS_MODEL,
    BRIEFING_FALLBACK_BASE_URL, BRIEFING_FALLBACK_API_KEY,
    BRIEFING_FALLBACK_MODEL, BRIEFING_FALLBACK_TIMEOUT,
)

logger = logging.getLogger(__name__)

_key_index_path = OUTPUT_DIR / ".llm_key_index"

# Process-local circuit breaker. If the upstream LLM has failed this many
# times in a row within a single process (pipeline run), skip remaining LLM
# calls. Previously, a single Groq load-shedding incident (503 with a long
# Retry-After) would cascade through every AI feature in a run and stretch
# runtimes to 5+ hours. Tripping the breaker caps the blast radius.
_LLM_CIRCUIT_THRESHOLD = int(os.environ.get("LLM_CIRCUIT_THRESHOLD", "3"))
_consecutive_failures = 0
_circuit_tripped = False


def _record_success() -> None:
    global _consecutive_failures, _circuit_tripped
    _consecutive_failures = 0
    _circuit_tripped = False


def _record_failure() -> None:
    global _consecutive_failures, _circuit_tripped
    _consecutive_failures += 1
    if _consecutive_failures >= _LLM_CIRCUIT_THRESHOLD:
        _circuit_tripped = True


def _circuit_open() -> bool:
    return _circuit_tripped


def reset_circuit() -> None:
    """Reset the circuit breaker. Call at the start of each pipeline run."""
    global _consecutive_failures, _circuit_tripped
    _consecutive_failures = 0
    _circuit_tripped = False


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
    """Return a requests session.

    No urllib3 retry layer: when the provider returns 429/503 with a long
    Retry-After header (Groq load-shedding), urllib3 respects it and sleeps
    the full duration per retry. That turned a single load-shed into hours
    of blocked pipeline time. We let the outer loop handle failures by
    rotating keys instead.
    """
    return requests.Session()


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
             response_format: dict | None = None,
             caller: str | None = None,
             model: str | None = None) -> str:
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
    if _circuit_open():
        raise RuntimeError(
            f"LLM circuit breaker open: >= {_LLM_CIRCUIT_THRESHOLD} consecutive failures"
        )

    url = f"{LLM_BASE_URL.rstrip('/')}/chat/completions"
    base_payload = {
        "model": model or LLM_MODEL,
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
    # Groq responds in <5s for typical briefing prompts. 30s covers long
    # generation + modest network jitter without dragging a single stuck call
    # into multi-minute territory. Tunable via LLM_TIMEOUT env var.
    timeout = float(os.environ.get("LLM_TIMEOUT", "30"))

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
                resp = session.post(url, json=payload, headers=headers, timeout=timeout)
                if resp.status_code == 429:
                    logger.warning(f"Key {attempt + 1} rate-limited (429), trying next...")
                    _advance_key()
                    last_error = f"429 on key {attempt + 1}"
                    break  # break inner while → outer for picks next key
                if resp.status_code in (500, 502, 503, 504):
                    # Upstream unavailable — skip this key immediately rather
                    # than retrying (urllib3 retry used to respect
                    # Retry-After and block for the entire header duration).
                    logger.warning(
                        "Key %d got %d from upstream, trying next...",
                        attempt + 1, resp.status_code,
                    )
                    last_error = f"{resp.status_code} on key {attempt + 1}"
                    break
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
                _record_success()
                # Usage tracking is pure observability — guard so a bug
                # in groq_usage can't break any LLM call. The response
                # body carries OpenAI-style {"usage": {"prompt_tokens",
                # "completion_tokens", "total_tokens"}} which we record
                # per-key and per-caller in data/state/groq_usage.json.
                try:
                    from modules.groq_usage import record_usage
                    record_usage(api_key, data, caller=caller)
                except Exception as _e:
                    logger.debug("groq_usage record failed: %s", _e)
                return data["choices"][0]["message"]["content"].strip()
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 429:
                    logger.warning(f"Key {attempt + 1} rate-limited, trying next...")
                    _advance_key()
                    last_error = str(e)
                    break  # break inner while → outer for picks next key
                raise
            except requests.exceptions.Timeout as e:
                logger.warning(
                    "Key %d timed out after %ss, trying next...",
                    attempt + 1, timeout,
                )
                last_error = f"timeout on key {attempt + 1}: {e}"
                break
            except requests.exceptions.ConnectionError as e:
                logger.warning(
                    "Key %d connection error, trying next: %s", attempt + 1, e,
                )
                last_error = f"connection error on key {attempt + 1}: {e}"
                break

    _record_failure()
    raise RuntimeError(f"All {attempts} API keys exhausted: {last_error}")


def is_available() -> bool:
    """Check if any LLM API key is configured."""
    return bool(LLM_API_KEY)


# ---------------------------------------------------------------------------
# Featherless.ai — paid OpenAI-compatible provider.
#
# Used ONLY for the daily global briefing where Groq free-tier 6K TPM is
# the bottleneck (briefing prompt ~7-8K). The token is shared across
# multiple projects (effective platform-wide concurrency ≈ 1 for cost-4
# models like deepseek-ai/DeepSeek-V3.2/kimi-k2/glm46), so this client makes a SINGLE
# attempt and surfaces failure to the caller — callers fall back to Groq
# rather than retrying. Retrying here would just queue against other
# projects holding the slot and make the contention worse.
# ---------------------------------------------------------------------------


def featherless_available() -> bool:
    """Check if Featherless is configured."""
    return bool(FEATHERLESS_API_KEY)


def call_featherless(user_content: str, system_prompt: str,
                     max_tokens: int = 2000,
                     response_format: dict | None = None,
                     caller: str | None = None,
                     model: str | None = None) -> str:
    """Single-shot call to Featherless.ai.

    Returns the model reply on success; raises RuntimeError on any failure
    (no retries, no key rotation — Featherless gives one key per subscription
    and contention against other projects is best handled by the caller's
    Groq fallback path, not by retrying here).

    The ``response_format`` graceful-fallback (retry once without the field
    if the provider returns 400 mentioning ``response_format``) mirrors
    ``call_llm`` so JSON-mode callers don't break on models that don't
    natively support it (DeepSeek, GLM).
    """
    if not FEATHERLESS_API_KEY:
        raise RuntimeError("Featherless not configured (FEATHERLESS_API_KEY unset)")

    url = f"{FEATHERLESS_BASE_URL.rstrip('/')}/chat/completions"
    payload: dict = {
        "model": model or FEATHERLESS_MODEL,
        "max_tokens": max_tokens,
        "temperature": 0.3,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    }
    if response_format is not None:
        payload["response_format"] = response_format

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {FEATHERLESS_API_KEY}",
    }
    # Featherless big models can take 20-40s on cold infer; give more
    # headroom than Groq while still capping the worst case.
    timeout = float(os.environ.get("FEATHERLESS_TIMEOUT", "60"))
    allow_response_format_fallback = response_format is not None

    while True:
        try:
            session = _get_http_session()
            resp = session.post(url, json=payload, headers=headers, timeout=timeout)
            if allow_response_format_fallback and _response_format_unsupported(resp):
                logger.warning(
                    "Featherless rejected response_format on %s; retrying once without it.",
                    payload["model"],
                )
                payload = {k: v for k, v in payload.items() if k != "response_format"}
                allow_response_format_fallback = False
                continue
            if resp.status_code == 429:
                # Concurrency exhausted (shared token, another project holds the slot).
                # Surface immediately so the caller can fall back to Groq.
                raise RuntimeError("Featherless 429 (concurrency exhausted)")
            if resp.status_code in (500, 502, 503, 504):
                raise RuntimeError(f"Featherless {resp.status_code} (upstream unavailable)")
            resp.raise_for_status()
            data = resp.json()
            try:
                from modules.groq_usage import record_usage
                # Tag caller with provider prefix so usage is distinguishable
                # from Groq calls in the shared usage file.
                tagged_caller = f"featherless:{caller}" if caller else "featherless"
                record_usage(FEATHERLESS_API_KEY, data, caller=tagged_caller)
            except Exception as _e:
                logger.debug("featherless usage record failed: %s", _e)
            return data["choices"][0]["message"]["content"].strip()
        except requests.exceptions.Timeout as e:
            raise RuntimeError(f"Featherless timeout after {timeout}s: {e}") from e
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(f"Featherless connection error: {e}") from e
        except requests.exceptions.HTTPError as e:
            raise RuntimeError(f"Featherless HTTP error: {e}") from e


# ---------------------------------------------------------------------------
# Secondary briefing provider — any authenticated OpenAI-compatible API used
# as the 2nd-tier briefing fallback (Featherless → this → Groq). Configured via
# BRIEFING_FALLBACK_* (base URL + optional bearer key + model). Replaces the
# retired Claude Bridge slot. Single-shot, no retries — a failure here defers
# to the caller's next tier (base Groq) rather than hammering a struggling
# provider. Sends response_format so JSON output is encouraged; callers still
# tolerate non-strict JSON via _parse_json downstream.
# ---------------------------------------------------------------------------


def briefing_fallback_available() -> bool:
    """Check if the secondary briefing provider is configured."""
    return bool(BRIEFING_FALLBACK_BASE_URL)


def call_briefing_fallback(user_content: str, system_prompt: str,
                           max_tokens: int = 2000,
                           response_format: dict | None = None,
                           caller: str | None = None,
                           model: str | None = None) -> str:
    """Single-shot call to the secondary briefing provider (any authenticated
    OpenAI-compatible API, e.g. Cerebras).

    Returns the model reply on success; raises RuntimeError on any failure. No
    retries — a failure here is best handled by the caller's next fallback tier
    (base Groq), not by piling on more requests to a struggling provider.

    Sends `BRIEFING_FALLBACK_API_KEY` as a bearer when set (blank => no auth
    header, for a keyless target).
    """
    if not BRIEFING_FALLBACK_BASE_URL:
        raise RuntimeError(
            "Briefing fallback not configured (BRIEFING_FALLBACK_BASE_URL unset)"
        )

    url = f"{BRIEFING_FALLBACK_BASE_URL.rstrip('/')}/chat/completions"
    payload: dict = {
        "model": model or BRIEFING_FALLBACK_MODEL,
        "max_tokens": max_tokens,
        "temperature": 0.3,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    }
    if response_format is not None:
        payload["response_format"] = response_format

    headers = {"Content-Type": "application/json"}
    if BRIEFING_FALLBACK_API_KEY:
        headers["Authorization"] = f"Bearer {BRIEFING_FALLBACK_API_KEY}"
    timeout = BRIEFING_FALLBACK_TIMEOUT

    try:
        session = _get_http_session()
        resp = session.post(url, json=payload, headers=headers, timeout=timeout)
        if resp.status_code == 504:
            raise RuntimeError("Briefing fallback 504 (upstream timeout)")
        if resp.status_code in (500, 502, 503):
            raise RuntimeError(
                f"Briefing fallback {resp.status_code} (upstream unavailable)"
            )
        resp.raise_for_status()
        data = resp.json()
        try:
            from modules.groq_usage import record_usage
            tagged_caller = f"briefing_fallback:{caller}" if caller else "briefing_fallback"
            record_usage("briefing-fallback-session", data, caller=tagged_caller)
        except Exception as _e:
            logger.debug("briefing_fallback usage record failed: %s", _e)
        return data["choices"][0]["message"]["content"].strip()
    except requests.exceptions.Timeout as e:
        raise RuntimeError(f"Briefing fallback timeout after {timeout}s: {e}") from e
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(f"Briefing fallback connection error: {e}") from e
    except requests.exceptions.HTTPError as e:
        raise RuntimeError(f"Briefing fallback HTTP error: {e}") from e
