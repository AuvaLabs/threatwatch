# LLM Provider Strategy

ThreatWatch's AI features call OpenAI-compatible `/chat/completions` endpoints
through `modules/llm_client.py` (base tier + key rotation) and
`modules/briefing_generator.py` (`_call_openai_compatible` 3-tier ladder). Any
provider with an OpenAI-compatible endpoint drops in via `.env` — no code
change. `scripts/test_free_llms.py` probes candidates against the two real
workloads before you wire them.

## Two workloads, different needs

| Workload | Volume/run | Needs | Tier |
|---|---|---|---|
| Article classify / escalation / **summaries** | dozens–hundreds | high **RPD**, speed | base (`LLM_*`) |
| Briefing / regional digests / top stories / profiles | ~5 | context + JSON + quality | briefing (`FEATHERLESS_*` slot) |

The briefing runs **first** after the per-run circuit-breaker reset
(`modules/ai_enrichment.py`), so it always gets first crack at a rate budget —
the high-volume summaries degrade first under pressure, not the flagship brief.

## The redundancy rule (learned the hard way — 2026-07 outage)

**No two tiers may resolve to the same base URL / same account.** The July 2026
outage happened because `LLM_*`, `FEATHERLESS_*`, and the "Groq" fallback were
all repointed at `api.deepinfra.com`; one account hitting a 402 took down all
three "tiers" at once. Keep each tier on a genuinely independent provider.

## Free providers (from awesome-free-llm-apis), ranked for our use

| Provider | Base URL | Free ceiling | Role | Key? |
|---|---|---|---|---|
| Groq | `https://api.groq.com/openai/v1` | 30 RPM / 1000 RPD | base (classify/summaries) | free, no CC |
| Cerebras | `https://api.cerebras.ai/v1` | 30 RPM / 14,400 RPD (8K ctx) | base headroom | free, no CC |
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta/openai` | 15 RPM / 1500 RPD | briefing | free (US only) |
| SambaNova | `https://api.sambanova.ai/v1` | 20 RPM / 20 RPD | briefing alt | free, no CC |
| Mistral | `https://api.mistral.ai/v1` | ~1 RPS / 500K TPM | briefing alt | free, no CC |
| NVIDIA NIM | `https://integrate.api.nvidia.com/v1` | ~40 RPM | quality fallback | free (dev program) |
| OpenRouter | `https://openrouter.ai/api/v1` | 20 RPM / 200 RPD | aggregator fallback | free, no CC |
| **LLM7.io** | `https://api.llm7.io/v1` | 30 RPM keyless / 120 w/token | **keyless backstop** | none |

## Current state (live — 2026-07-15)

Two independent providers, so the flagship briefing does not depend on Groq:

```env
# Base — high-volume classify / summaries / regional digests / top stories +
# briefing final fallback. 3 Groq keys rotated => ~3x free-tier budget;
# summaries no longer 429 (validated: 130 enriched, 0 rate-limits).
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_MODEL=llama-3.3-70b-versatile
LLM_API_KEYS=<groq_key_1>,<groq_key_2>,<groq_key_3>
BRIEFING_MODEL=llama-3.1-8b-instant       # base briefing fallback (fits 70B TPM)
TOP_STORIES_MODEL=llama-3.1-8b-instant

# Briefing primary — Gemini free tier, INDEPENDENT of Groq. `gemini-flash-lite-latest`
# is the model this free account can call (gemini-2.5-* are gated for new accts);
# validated 0.9s/valid-JSON. Rides the FEATHERLESS_* slot (auth-capable path).
FEATHERLESS_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
FEATHERLESS_API_KEY=<gemini_key>
FEATHERLESS_MODEL=gemini-flash-lite-latest

# Claude Bridge — DISABLED (operator directive 2026-07-15). Empty => skipped.
CLAUDE_BRIDGE_URL=
```

Briefing ladder: **Gemini → Groq-8B** (base fallback). Base everything else: Groq.
featherless.ai is **dead** (subscription lapsed — "active plan required"). Snapshots:
`.env.bak-outage-2026-07` (DeepInfra), `.env.bak-llm7-emergency` (LLM7), `.env.bak-pre-gemini`.

### Tested spares (swap-in ready, not live)

Both validated with `scripts/test_free_llms.py`; stored as `# SPARE_*` comments in `.env`.
- **Cerebras** — `https://api.cerebras.ai/v1`, `gpt-oss-120b`, 14,400 RPD (8K ctx). `csk-` key.
- **LLM7.io** — `https://api.llm7.io/v1`, `codestral-latest`, keyless (any/no bearer).

To promote a spare: drop its base_url/model/key into `FEATHERLESS_*` (briefing) or
`LLM_*` (base). Note: the auth-capable slots are `LLM_*` and `FEATHERLESS_*`; the
2nd-tier `CLAUDE_BRIDGE_*` slot sends no Authorization header (keyless targets
only) and is currently disabled. Adding a 3rd authenticated briefing tier would
need a small llm_client change (optional bearer on that slot).

Validate any change with: `GROQ_API_KEY=... GEMINI_API_KEY=... python3 scripts/test_free_llms.py`
