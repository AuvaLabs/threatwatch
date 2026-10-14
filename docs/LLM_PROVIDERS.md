# LLM provider strategy

ThreatWatch sends all AI capabilities through the shared client in
`modules/llm_client.py`. The client supports the native Claude Messages API and
OpenAI-compatible endpoints. A provider or model failure cannot silently
disable every intelligence product because the route retains independent
fallback endpoints.

## Routing order

1. Native `ANTHROPIC_*` provider when configured.
2. Primary `LLM_*` provider, including primary key rotation.
3. `FEATHERLESS_*` fallback.
4. `BRIEFING_FALLBACK_*` fallback.
5. Deterministic product behavior, such as the normal digest or a labeled stale
   last-known-good artifact.

Despite their historical names, both fallback configurations apply to every AI
capability: briefings, top stories, summaries, classification, incident
synthesis, CVE narratives, and actor profiles.

Duplicate protocol, endpoint, and model combinations are removed from the route
so a provider is not called twice under different configuration names.

## Native Claude configuration

```env
ANTHROPIC_API_KEY=your-claude-api-key
ANTHROPIC_BASE_URL=https://api.anthropic.com/v1
ANTHROPIC_MODEL=claude-haiku-5-5
ANTHROPIC_BRIEFING_MODEL=claude-sonnet-5-5
ANTHROPIC_TOP_STORIES_MODEL=claude-sonnet-5-5
ANTHROPIC_TIMEOUT=60
```

The native provider sends bulk calls to Haiku. Briefing and top-story callers
select Sonnet through their task-specific model settings. If native Claude
fails, the task-specific Claude model is not forwarded to another provider.
The next provider uses its own configured model.

The canonical AuvaLabs key is stored in the gitignored operator secret at
`kb_center/secrets/anthropic.env`. Each deployment copies it to the gitignored
runtime file `.secrets/anthropic.env`. Set `ANTHROPIC_ENV_FILE` when a host uses
a different runtime path. Keep the literal out of the ThreatWatch repository
and documentation.

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

- Native Claude uses `POST /v1/messages`, `x-api-key`, and the required API
  version header. Native responses are normalized for shared usage telemetry.
- OpenAI-style `response_format` is not sent to Claude. Existing prompts and
  downstream schema validation enforce JSON for structured capabilities.
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
