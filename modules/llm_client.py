"""Resilient OpenAI-compatible client with provider and key failover."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

import requests

from modules.config import (
    BRIEFING_FALLBACK_API_KEY,
    BRIEFING_FALLBACK_BASE_URL,
    BRIEFING_FALLBACK_MODEL,
    BRIEFING_FALLBACK_TIMEOUT,
    FEATHERLESS_API_KEY,
    FEATHERLESS_BASE_URL,
    FEATHERLESS_MODEL,
    FEATHERLESS_TIMEOUT,
    LLM_API_KEY,
    LLM_API_KEYS,
    LLM_BASE_URL,
    LLM_MODEL,
    OUTPUT_DIR,
)

logger = logging.getLogger(__name__)

_key_index_path = OUTPUT_DIR / ".llm_key_index"
_LLM_CIRCUIT_THRESHOLD = int(os.environ.get("LLM_CIRCUIT_THRESHOLD", "3"))
_KIMI_MIN_MAX_TOKENS = 512
_KIMI_DEFAULT_TIMEOUT = 120
_consecutive_failures = 0
_circuit_tripped = False
_last_provider = ""


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    model: str
    keys: tuple[str, ...]
    timeout: float
    rotate_keys: bool = False


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
    global _consecutive_failures, _circuit_tripped
    _consecutive_failures = 0
    _circuit_tripped = False


def _read_key_index() -> int:
    try:
        return int(_key_index_path.read_text().strip()) if _key_index_path.exists() else 0
    except (ValueError, OSError):
        return 0


def _write_key_index(index: int) -> None:
    try:
        _key_index_path.parent.mkdir(parents=True, exist_ok=True)
        _key_index_path.write_text(str(index))
    except OSError:
        pass


def _next_api_key() -> str:
    if len(LLM_API_KEYS) <= 1:
        return LLM_API_KEY
    index = _read_key_index()
    key = LLM_API_KEYS[index % len(LLM_API_KEYS)]
    _write_key_index((index + 1) % len(LLM_API_KEYS))
    return key


def _advance_key() -> None:
    if LLM_API_KEYS:
        _write_key_index((_read_key_index() + 1) % len(LLM_API_KEYS))


def _get_http_session() -> requests.Session:
    return requests.Session()


def _is_kimi_base(base_url: str) -> bool:
    return "api.kimi.com/coding/v1" in base_url


def _is_kimi_endpoint() -> bool:
    return _is_kimi_base(LLM_BASE_URL)


def _primary_timeout() -> float:
    default = _KIMI_DEFAULT_TIMEOUT if _is_kimi_endpoint() else 30
    return float(os.environ.get("LLM_TIMEOUT", str(default)))


def _configured_providers(model_override: str | None = None) -> list[Provider]:
    providers: list[Provider] = []
    primary_keys = (
        tuple(LLM_API_KEYS) or (LLM_API_KEY,)
        if LLM_API_KEY else ()
    )
    if LLM_BASE_URL and primary_keys:
        providers.append(Provider(
            "kimi" if _is_kimi_endpoint() else "primary",
            LLM_BASE_URL,
            model_override or LLM_MODEL,
            primary_keys,
            _primary_timeout(),
            rotate_keys=True,
        ))
    if FEATHERLESS_BASE_URL and FEATHERLESS_API_KEY and FEATHERLESS_MODEL:
        providers.append(Provider(
            "featherless", FEATHERLESS_BASE_URL, FEATHERLESS_MODEL,
            (FEATHERLESS_API_KEY,), FEATHERLESS_TIMEOUT,
        ))
    if BRIEFING_FALLBACK_BASE_URL and BRIEFING_FALLBACK_MODEL:
        keys = ((BRIEFING_FALLBACK_API_KEY,) if BRIEFING_FALLBACK_API_KEY else ("",))
        providers.append(Provider(
            "fallback", BRIEFING_FALLBACK_BASE_URL, BRIEFING_FALLBACK_MODEL,
            keys, BRIEFING_FALLBACK_TIMEOUT,
        ))
    unique: list[Provider] = []
    seen: set[tuple[str, str]] = set()
    for provider in providers:
        identity = (provider.base_url.rstrip("/"), provider.model)
        if identity not in seen:
            unique.append(provider)
            seen.add(identity)
    return unique


def _payload(provider: Provider, user_content: str, system_prompt: str,
             max_tokens: int, response_format: dict | None) -> dict[str, Any]:
    effective_tokens = max_tokens
    if _is_kimi_base(provider.base_url) and effective_tokens < _KIMI_MIN_MAX_TOKENS:
        effective_tokens = _KIMI_MIN_MAX_TOKENS
    payload: dict[str, Any] = {
        "model": provider.model,
        "max_tokens": effective_tokens,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    }
    if not _is_kimi_base(provider.base_url):
        payload["temperature"] = 0.3
    if response_format is not None:
        payload["response_format"] = response_format
    return payload


def _response_format_unsupported(response: requests.Response) -> bool:
    return response.status_code == 400 and "response_format" in response.text.lower()


def _provider_keys(provider: Provider) -> list[str]:
    attempts = min(len(provider.keys), 3) if len(provider.keys) > 1 else 1
    if provider.rotate_keys:
        return [_next_api_key() for _ in range(attempts)]
    return list(provider.keys[:attempts])


def _record_usage(api_key: str, data: dict, caller: str | None, provider: Provider) -> None:
    try:
        from modules.groq_usage import record_usage
        label = f"{provider.name}:{caller}" if caller else provider.name
        record_usage(api_key or provider.name, data, caller=label)
    except Exception as exc:
        logger.debug("LLM usage record failed: %s", exc)


def _call_provider(provider: Provider, user_content: str, system_prompt: str,
                   max_tokens: int, response_format: dict | None,
                   caller: str | None) -> str:
    url = f"{provider.base_url.rstrip('/')}/chat/completions"
    last_error = "provider unavailable"
    for attempt, api_key in enumerate(_provider_keys(provider), 1):
        payload = _payload(provider, user_content, system_prompt, max_tokens, response_format)
        allow_format_retry = response_format is not None
        while True:
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            try:
                response = _get_http_session().post(
                    url, json=payload, headers=headers, timeout=provider.timeout,
                )
                if _response_format_unsupported(response) and allow_format_retry:
                    payload = {k: v for k, v in payload.items() if k != "response_format"}
                    allow_format_retry = False
                    continue
                if response.status_code in (429, 500, 502, 503, 504):
                    last_error = f"HTTP {response.status_code}"
                    if response.status_code == 429 and provider.rotate_keys:
                        _advance_key()
                    break
                response.raise_for_status()
                data = response.json()
                content = data["choices"][0]["message"]["content"].strip()
                if not content:
                    raise RuntimeError("empty provider response")
                _record_usage(api_key, data, caller, provider)
                return content
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
                last_error = type(exc).__name__
                break
            except (requests.exceptions.HTTPError, KeyError, TypeError, ValueError) as exc:
                last_error = type(exc).__name__
                break
        logger.warning(
            "LLM provider %s attempt %d failed: %s",
            provider.name, attempt, last_error,
        )
    raise RuntimeError(f"provider {provider.name} exhausted: {last_error}")


def call_llm(user_content: str, system_prompt: str, max_tokens: int = 2000,
             response_format: dict | None = None, caller: str | None = None,
             model: str | None = None) -> str:
    """Call configured providers in order and return the first valid response."""
    global _last_provider
    if _circuit_open():
        raise RuntimeError(
            f"LLM circuit breaker open: >= {_LLM_CIRCUIT_THRESHOLD} consecutive failures"
        )
    providers = _configured_providers(model)
    if not providers:
        raise RuntimeError("No LLM provider configured")
    failures: list[str] = []
    for provider in providers:
        try:
            result = _call_provider(
                provider, user_content, system_prompt, max_tokens,
                response_format, caller,
            )
            _last_provider = f"{provider.name}/{provider.model}"
            _record_success()
            return result
        except RuntimeError:
            failures.append(provider.name)
    _record_failure()
    raise RuntimeError(f"All providers exhausted: {', '.join(failures)}")


def last_provider_label() -> str:
    return _last_provider


def clear_last_provider() -> None:
    global _last_provider
    _last_provider = ""


def is_available() -> bool:
    return bool(_configured_providers())
