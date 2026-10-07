# LLM provider strategy

ThreatWatch sends all AI capabilities through the shared OpenAI-compatible
client in `modules/llm_client.py`. A provider or model failure cannot silently
disable every intelligence product because the client supports two independent
fallback endpoints.

## Routing order

1. Primary `LLM_*` provider, including primary key rotation.
2. `FEATHERLESS_*` fallback.
3. `BRIEFING_FALLBACK_*` fallback.
4. Deterministic product behavior, such as the normal digest or a labeled stale
   last-known-good artifact.

Despite their historical names, both fallback configurations apply to every AI
capability: briefings, top stories, summaries, classification, incident
synthesis, CVE narratives, and actor profiles.

Duplicate endpoint and model pairs are removed from the route so a provider is
not called twice under different configuration names.

## Primary configuration

```env
LLM_API_KEY=your-primary-key
LLM_BASE_URL=https://api.kimi.com/coding/v1
LLM_MODEL=kimi-for-coding
LLM_PROVIDER=openai
BRIEFING_MODEL=kimi-for-coding
TOP_STORIES_MODEL=kimi-for-coding
LLM_TIMEOUT=120
```

Any OpenAI-compatible `/chat/completions` endpoint can be used. Never assume a
provider's model name remains valid indefinitely. Validate the configured model
with a smoke request before deployment and monitor `/api/v1/health/ai`.

## Fallback configuration

```env
FEATHERLESS_API_KEY=your-first-fallback-key
FEATHERLESS_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
FEATHERLESS_MODEL=gemini-flash-lite-latest
FEATHERLESS_TIMEOUT=60

BRIEFING_FALLBACK_API_KEY=your-second-fallback-key
BRIEFING_FALLBACK_BASE_URL=https://api.cerebras.ai/v1
BRIEFING_FALLBACK_MODEL=gpt-oss-120b
BRIEFING_FALLBACK_TIMEOUT=60
```

Provider-specific models are used on fallback routes. A primary task-specific
model override is never sent to a different provider.

## Compatibility behavior

- Kimi coding endpoints omit `temperature`, because they reject values other
  than their supported default.
- Kimi calls receive a minimum output-token budget and a longer default timeout.
- A provider that rejects `response_format` is retried once without that field.
- HTTP 429, timeout, connection, 5xx, invalid payload, and retired-model errors
  fall through to the next configured provider.
- Error responses are logged without API keys or response bodies.
- The provider that served an artifact is recorded with that artifact.

## Health contract

`/api/v1/health/ai` reports freshness for the global briefing, top stories, and
all three regional briefings. `/api/health` becomes `degraded` when a critical
artifact is stale or when the latest enrichment run reports a capability
failure.
