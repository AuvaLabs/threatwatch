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

Briefing ladder = **three independent providers**; base everything else = Groq:
**Gemini → Cerebras → Groq-8B**.

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
# validated 0.9s/valid-JSON. Rides the FEATHERLESS_* slot.
FEATHERLESS_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
FEATHERLESS_API_KEY=<gemini_key>
FEATHERLESS_MODEL=gemini-flash-lite-latest

# Briefing 2nd tier — Cerebras (independent of both Gemini and Groq). Engages
# only if Gemini fails; validated 0.5s/valid-JSON. New generic authenticated
# slot (replaces the retired Claude Bridge; sends the key as a bearer).
BRIEFING_FALLBACK_BASE_URL=https://api.cerebras.ai/v1
BRIEFING_FALLBACK_API_KEY=<cerebras_csk_key>
BRIEFING_FALLBACK_MODEL=gpt-oss-120b
```

featherless.ai is **dead** (subscription lapsed) and the **Claude Bridge is
retired** (operator directive). The three briefing tiers are on three different
infra stacks (Google / Cerebras / Groq) — no single account's exhaustion can
blackout the flagship briefing. Snapshots: `.env.bak-outage-2026-07` (DeepInfra),
`.env.bak-llm7-emergency`, `.env.bak-pre-gemini`, `.env.bak-pre-cerebras`.

### Tested spare (swap-in ready, not live)

- **LLM7.io** — `https://api.llm7.io/v1`, `codestral-latest`, **keyless** (any/no
  bearer). Break-glass: drop into any slot (base `LLM_*`, briefing `FEATHERLESS_*`,
  or 2nd-tier `BRIEFING_FALLBACK_*`) if a live provider lapses. Validated via
  `scripts/test_free_llms.py`.

All three briefing slots (`LLM_*`, `FEATHERLESS_*`, `BRIEFING_FALLBACK_*`) are now
authenticated (Bearer) OR keyless-tolerant, so any OpenAI-compatible provider fits
any slot.

Validate any change with: `GROQ_API_KEY=... GEMINI_API_KEY=... python3 scripts/test_free_llms.py`
