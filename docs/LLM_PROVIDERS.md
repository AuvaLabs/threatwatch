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

## Current state (emergency — 2026-07-15)

All tiers point at **LLM7.io / `codestral-latest`** (keyless) to recover from the
DeepInfra 402. This restored briefing + regional digests + top stories.
Summaries partially rate-limit at 30 RPM (degrade to keyword — safe). Original
DeepInfra values are preserved as `# [outage-2026-07 was]` comments in `.env`
and `.env.bak-outage-2026-07`.

### Target tier mix (once free keys land)

```env
# Tier 1 — base: high-volume classify/summaries (add multiple keys to stack RPD)
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_MODEL=llama-3.3-70b-versatile
LLM_API_KEYS=<groq_key_1>,<groq_key_2>        # rotation multiplies RPD
BRIEFING_MODEL=llama-3.1-8b-instant
TOP_STORIES_MODEL=llama-3.1-8b-instant

# Tier 2 — briefing primary: context + quality, independent provider
FEATHERLESS_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
FEATHERLESS_API_KEY=<gemini_key>
FEATHERLESS_MODEL=gemini-2.5-flash

# Tier 3 — keyless backstop (never fully offline)
# briefing falls through to LLM7 if a real key is also placed there, or keep
# CLAUDE_BRIDGE pointed at a working shim.
```

Validate any change with: `GROQ_API_KEY=... GEMINI_API_KEY=... python3 scripts/test_free_llms.py`
