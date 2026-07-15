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

## Current state (restored — 2026-07-15)

After an LLM7-only emergency stopgap, the **diversified ladder is restored using
assets already on the box**: 3 working Groq keys (recovered from
`.env.bak.predeepinfra.2026-06-13`) + keyless LLM7 as the one non-Groq tier.
featherless.ai is **dead** (subscription lapsed — "active plan required"), so it
is out of the ladder entirely. Prior values preserved as `# [restore-2026-07 was]`
comments; snapshots at `.env.bak-outage-2026-07` (DeepInfra) and
`.env.bak-llm7-emergency` (LLM7-only).

```env
# Tier 1 — base: high-volume classify/summaries + briefing fallback.
# 3 Groq keys rotated => ~3x free-tier RPM/RPD; summaries no longer 429.
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_MODEL=llama-3.3-70b-versatile
LLM_API_KEYS=<groq_key_1>,<groq_key_2>,<groq_key_3>
BRIEFING_MODEL=llama-3.1-8b-instant       # base briefing fallback (fits 70B TPM)
TOP_STORIES_MODEL=llama-3.1-8b-instant

# Tier 2 — briefing primary: Groq gpt-oss-120b (bigger ctx + quality; ~1.7s).
FEATHERLESS_BASE_URL=https://api.groq.com/openai/v1
FEATHERLESS_API_KEY=<groq_key_1>
FEATHERLESS_MODEL=openai/gpt-oss-120b

# Tier 3 — independent keyless backstop: LLM7.io (the ONLY non-Groq tier, so a
# Groq-wide outage can't take briefing fully down). Rides the Claude Bridge slot.
CLAUDE_BRIDGE_URL=https://api.llm7.io/v1
CLAUDE_BRIDGE_MODEL=codestral-latest
```

**Optional upgrade** — for a briefing tier fully independent of Groq, drop a free
Gemini 2.5 Flash key into the FEATHERLESS slot
(`https://generativelanguage.googleapis.com/v1beta/openai`, US-eligible), pushing
Groq down to base-only. Validate first with `scripts/test_free_llms.py`.

Validate any change with: `GROQ_API_KEY=... GEMINI_API_KEY=... python3 scripts/test_free_llms.py`
