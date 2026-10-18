# LLM provider strategy

ThreatWatch sends all AI capabilities through the shared client in
`modules/llm_client.py`. The client supports the native Claude Messages API and
OpenAI-compatible endpoints. A provider or model failure cannot silently
disable every intelligence product because the route retains independent
fallback endpoints.

## Routing order

1. Bounded Model Services route for approved callers when configured.
2. Native `ANTHROPIC_*` provider when configured.
3. Primary `LLM_*` provider, including primary key rotation.
4. `FEATHERLESS_*` fallback.
5. `BRIEFING_FALLBACK_*` fallback.
6. Deterministic product behavior, such as the normal digest or a labeled stale
   last-known-good artifact.

Despite their historical names, both fallback configurations apply to every AI
capability: briefings, top stories, summaries, classification, incident
synthesis, CVE narratives, and actor profiles.

Duplicate protocol, endpoint, and model combinations are removed from the route
so a provider is not called twice under different configuration names.

## AuvaLabs Model Services configuration

Model Services uses a private gateway bearer token, not an OpenAI API key. Keep
the token in `.secrets/modelservices.env`:

```env
MODEL_SERVICES_API_KEY=your-gateway-token
```

Configure the bounded route in `.env`:

```env
MODEL_SERVICES_URL=https://modelservices.auvalabs.com/techmodel/servicesapi/chat
MODEL_SERVICES_MODEL=gpt-6-luna
MODEL_SERVICES_TIMEOUT=240
MODEL_SERVICES_REASONING_EFFORT=low
MODEL_SERVICES_CALLERS=briefing,top_stories
MODEL_SERVICES_DAILY_CALL_LIMIT=48
MODEL_SERVICES_CALLER_COOLDOWN_SECONDS=3600
LLM_ZERO_COST_PROVIDERS=modelservices,primary,fallback
```

The automated route supports only the global briefing and top-stories callers.
It uses `gpt-6-luna` with low reasoning, allows at most one attempt per caller
every hour, and permits at most 48 attempts per UTC day. Attempts are
reserved before network access, so failures and timeouts cannot bypass the
subscription guard. Regional briefings and bulk enrichment continue through
the normal provider chain. The gateway is reached over IPv4 because its edge
policy allowlists the production VPS IPv4 address.

Do not configure `gpt-6.1-sol` or `gpt-6-astra` for scheduled work. Those models
remain available for deliberate, manual analysis where their higher allowance
cost is justified.

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

## Usage accounting and budget behavior

Every successful response records input tokens, output tokens, caller, route,
model, and nominal cost in `data/state/api_costs.json`. The daily budget reads
that same ledger before each billable provider attempt. This prevents a token
telemetry file and a separate empty cost file from disagreeing.

```env
DAILY_BUDGET_USD=2.00
LLM_ZERO_COST_PROVIDERS=primary,fallback
```

Route names in `LLM_ZERO_COST_PROVIDERS` remain available after the paid budget
is reached. Only list a route when its configured account is actually free or
covered by a separate credit agreement. Current built-in nominal pricing covers
the configured Claude Haiku, Claude Sonnet, Gemini Flash Lite, and GPT OSS 120B
models. Unknown models are logged and counted as unpriced calls.

## Compatibility behavior

- Native Claude uses `POST /v1/messages`, `x-api-key`, and the required API
  version header. Native responses are normalized for shared usage telemetry.
- Model Services uses its exact gateway URL, sends the `chatgpt` provider field,
  omits unsupported structured-output fields, and pins transport to IPv4.
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
all three regional briefings. `/api/v1/health/artifacts` separately reports
Hunts and Threat Ledger generation and freshness. `/api/health` becomes
`degraded` when a critical artifact is stale or when the latest run reports a
capability failure.
