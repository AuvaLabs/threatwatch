# Changelog

All notable changes to ThreatWatch are documented here.

## 2026-05-03 — Multi-tier LLM routing for the daily briefing (Featherless → Claude Bridge → Groq+8B)

Context: the global briefing prompt (~7-8K) had been clamped (40 articles × 80 chars/summary × 1200 max_tokens) to fit Groq free-tier 6K TPM. That worked but left the briefing perpetually one feed-volume spike away from a 429-cliff and capped output detail at ~1200 tokens. Introduce a 3-tier cascade so the briefing has real headroom while still degrading gracefully when premium tiers fail.

### Added
- **Tier 1 — Featherless.ai (`modules/llm_client.py`, `modules/config.py`, `modules/briefing_generator.py`)**: paid OpenAI-compatible provider, `deepseek-v3.2` at 32K ctx. Primary path for the global briefing. Output cap raised 1200→4000 tokens (`feather_max_tokens` kwarg) since Featherless's 32K context allows a richer narrative without prompt clipping. Single-shot, no retries — token is shared across multiple of the operator's projects so 429 = step down. Env: `FEATHERLESS_API_KEY`, `FEATHERLESS_BASE_URL`, `FEATHERLESS_MODEL`, `FEATHERLESS_TIMEOUT`. Usage tagged `featherless:<caller>` in `data/state/groq_usage.json`.
- **Tier 2 — Claude Bridge (`modules/llm_client.py`, `modules/config.py`, `modules/briefing_generator.py`)**: host-local OpenAI-compatible shim that proxies to the `claude` CLI using a Claude Max subscription. Operated by RedBlue's claude-bridge service on the same host (port 8400). 2nd-tier briefing fallback — zero per-token cost, rate-limited by the shared Max session, ignores `max_tokens` and `response_format` (CLI doesn't expose them). Single-shot, 300s timeout. Env: `CLAUDE_BRIDGE_URL`, `CLAUDE_BRIDGE_MODEL`, `CLAUDE_BRIDGE_TIMEOUT`. Usage tagged `claude_bridge:<caller>`. Requires UFW allow rule for ThreatWatch's docker subnet (`172.21.0.0/16` → host:8400).
- **Tier 3 — Groq + `llama-3.1-8b-instant` (existing, last-resort)**: keeps the 1200-token cap so the prompt still fits free-tier headroom on Groq.
- **Per-provider routing kwargs (`briefing_generator._call_openai_compatible`)**: `prefer_featherless: bool` gates the cascade — only the global briefing opts in. Regional briefings, top_stories, attack_tagger, cve_narrative, ttp_extractor, and the hybrid classifier all stay on Groq direct (high-frequency or small-prompt callers don't need premium tiers and would crowd out other consumers). `feather_max_tokens: int | None` decouples the Featherless output cap from the Groq fallback cap.

### Architecture
- **Each tier is independent**: each has its own `*_available()` gate, and a failure on tier N never retries tier N — control flow drops straight to tier N+1. Failures log a warning naming which tier fell through, so live logs reveal which tier ultimately served any given briefing.
- **Featherless concurrency reality**: each big model (`deepseek-v3.2`, `kimi-k2`, `glm46-357b`) costs **4 concurrency** on Featherless and the Premium tier total is **4** — effective concurrent requests across all consumers ≈ 1. Briefing makes 1 call per pipeline run (~daily), so ThreatWatch's share is negligible.
- **Bridge auth**: bridge has no API key — it consumes the host's `~/.claude/` OAuth session. ThreatWatch sees only an HTTP endpoint; coordinate with RedBlue/ARBI before widening usage.

### Operations
- **Required `.env` for full cascade**: `FEATHERLESS_API_KEY=rc_...`, `FEATHERLESS_BASE_URL=https://api.featherless.ai/v1`, `FEATHERLESS_MODEL=deepseek-v3.2`, `CLAUDE_BRIDGE_URL=http://172.21.0.1:8400/v1`, `CLAUDE_BRIDGE_MODEL=sonnet`. Both layers are optional — without them the briefing keeps using Groq+8B as before.
- **Required UFW**: `sudo ufw allow from 172.21.0.0/16 to any port 8400 proto tcp comment "claude-bridge from threatwatch"` (only RedBlue's `172.25.0.0/16` was allowed before).
- **Startup logs** confirm wiring: `Featherless configured — global briefing will prefer deepseek-v3.2 (32K ctx); Groq+llama-3.1-8b-instant fallback.` and `Claude Bridge configured at http://172.21.0.1:8400/v1 (sonnet); 2nd-tier briefing fallback.`
- **`docker-compose.yml`**: `pipeline` service `environment:` block extended with `FEATHERLESS_*` and `CLAUDE_BRIDGE_*` passthroughs.

### Testing
- 1402 tests pass (up from 1380). +51 new tests across `test_featherless_client.py` (17), `test_claude_bridge_client.py` (13), `test_briefing_featherless_routing.py` (21). Coverage: per-provider single-shot policy (no retries on 429/5xx), `response_format` graceful fallback for DeepSeek/GLM (which don't natively support JSON mode), missing-config guards, usage-tagging, output-cap split (Featherless 4000 / Groq 1200), and the 3-tier cascade (Bridge takes over when Feather unavailable/fails, Groq when both fail, Bridge skipped on regional path).

## 2026-04-27 — Telegram outage RCA + fixes (briefing TPM, KEV full-corpus dispatch, 14d age cutoff)

Context: Telegram channel had been silent since 2026-04-26. Two independent root causes converged. Both fixed and pushed; 12 KEV alerts fired in the first hour after the fix landed (5 from manual force-run + 7 from natural pipeline ticks).

### Fixed
- **Briefing crossed Groq's per-request 6K TPM cap (`modules/config.py`, `modules/briefing_generator.py`, `docker-compose.yml`)**: every briefing 429'd on every key for 28h+ straight while classify/attack_llm/regional kept succeeding (their per-call sizes were under 6K). Critical insight: Groq's free-tier 6K TPM is enforced **per-request**, not just per-minute throughput — 3 rotating keys do NOT raise the per-call ceiling, and switching 70B→8B doesn't help (same 6K cap on all free-tier models). Fix: switch the global briefing call to `llama-3.1-8b-instant` (env: `BRIEFING_MODEL`), drop `_MAX_BRIEFING_ARTICLES` 80→40, `_DIGEST_SUMMARY_CHARS` 250→80, `max_tokens` 2000→1200. Real probe: 4,450 prompt + 473 completion = 4,933 tokens (~350 token margin under cap). Regional briefings keep the 80-article cap (their per-call size was already fine).
- **KEV alerts dispatched against the new fetch batch only (`threatdigest_main.py`)**: most KEV-tagged articles are older items already deduplicated out (CVE coverage takes hours/days to surface; CISA can list a CVE long after the article was first enriched). Result: `KEV: flagged 0 articles` every tick despite 12+ KEV CVEs in the live corpus. Fix: dispatch against `all_articles` (full `daily_latest.json` corpus) with KEV enricher re-applied so newly-listed CVEs are caught on older articles.
- **`scripts/cleanup.py` ModuleNotFoundError at scheduler startup**: missing `sys.path` bootstrap caused `from modules.config import ...` to crash on every scheduler tick (cleanup ran with exit code 1, then pipeline continued without cleanup). Added the standard 2-line bootstrap.

### Added
- **TELEGRAM_KEV_MAX_AGE_DAYS (default 14) (`modules/telegram.py`)**: suppresses KEV alerts whose `date_added` is older than the cutoff. Stale CVEs are silently stamped into the dedup state so they never alert AND never retry on later runs. Set to 0 to disable the filter (alerts every never-before-seen KEV CVE — pre-2026-04-27 behavior). Defensive: missing or unparseable `date_added` falls through to the main loop instead of being silently silenced. Necessary because today's full-corpus dispatch fix initially fired alerts for 5 CVEs that have been on KEV for 90+ days (oldest = 315 days) — technically still "actively exploited" per CISA, but alerting a year-old listing as breaking news was misleading.

### Operations
- **Briefing model is env-tunable (`BRIEFING_MODEL` in `.env`)**, default `llama-3.1-8b-instant`. Set to `llama-3.3-70b-versatile` only if the prompt is also brought back under 6K (today it isn't).
- **Backfill drain complete** for KEV alerts: 12 alerts sent, 12 KEV CVEs in corpus, 0 pending. From here on only freshly-listed CVEs (within `TELEGRAM_KEV_MAX_AGE_DAYS`) trigger alerts.

### Testing
- 142 tests pass on the changed surface (`test_briefing_generator`, `test_briefing_gen`, `test_telegram`, `test_kev_enricher`). +4 new telegram tests for the cutoff: stale-silenced-not-sent, fresh-alerts, filter-off (`=0`), malformed-date fallthrough.

## 2026-04-25 — Cache-staleness fixes, historical enrichment backfills, top_stories on 8B

Context: the free-tier capitalization features shipped 2026-04-23 were verified live this session — `cve_narrative`, `ttp_extract`, and `attack_llm` all firing in production telemetry. Two regressions surfaced and got fixed: top_stories had been silently returning stale 28-hour-old selections (cache had no TTL), and once that fix landed it 429'd every cycle because its 70B prompt loses TPM contention against briefing/regional that fire seconds before. 1129 historical articles were also backfilled with the new enrichers (366 TTPs, 37 CVE narratives, 446 summaries) — ~63% of the ~2300-article corpus brought up to current enrichment standards in one pass.

### Fixed
- **top_stories cache staleness (`modules/top_stories.py`)**: `ai_cache` has no read-side TTL, so a digest-only cache key let `top_stories` return the same selection forever when fuzzy-dedup was making the corpus near-static day-to-day. Observed: 28 hours since the last LLM call despite a 1-hour cooldown window. Fix: bucket the cache key by UTC date (`topstories_2026-04-25_<digest_hash>`) so the editorial pass is forced to rerun ≥1×/day even when the underlying digest hash is unchanged.
- **top_stories TPM contention (`modules/llm_client.py`, `modules/briefing_generator.py`, `modules/top_stories.py`)**: the AI enrichment chain runs briefing → regional (×3) → top_stories → summaries back-to-back. By the time `top_stories`' 5K-token 70B prompt fires, every key has 429'd from the burst. Plumbed an optional `model` kwarg through `call_llm` and `_call_openai_compatible` so callers can opt into a lighter Groq model. `top_stories` now defaults to `llama-3.1-8b-instant` (env: `TOP_STORIES_MODEL`) and caps its digest at 30 articles (env: `TOP_STORIES_MAX_ARTICLES`) to fit 8B's 8K context window — editorial selection doesn't need 70B's depth, and the smaller token cost fits within the TPM left after briefing/regional. Verified live: ~3.5K tokens/call, 8 stories generated, `provider: openai/llama-3.1-8b-instant`.
- **backfill_summaries TPM trips (`scripts/backfill_summaries.py`)**: original script blasted batches with no inter-pass delay, tripped the circuit breaker mid-run under contention with the live pipeline. Added `BACKFILL_SUMMARY_SLEEP` between passes (default 10s), a `reset_circuit()` per pass, and a single retry-after-pause on empty pass — a streak of transient 429s no longer truncates the run.

### Added
- **Daily-average AI tokens tile (`threatwatch.html`)**: today's count is partial and resets each midnight UTC, which made the bottom-left tile read low for most of the day. Switched to a daily average computed from `/api/groq-usage`'s `last_7d` window (today excluded as partial). Tile label is now "AI TOKENS / DAY"; tooltip retains today-so-far for context.
- **Historical CVE narrative backfill script (`scripts/backfill_cve_narratives.py`)**: one-shot iteration over `daily_latest.json` running the existing `cve_narrative` enricher against qualifying CVEs (CVSS ≥ 8.0 or EPSS percentile ≥ 0.80) that lack a narrative. Writes back via merge-by-hash and mirrors into SQLite. 8s pacing, 3 lifetime backoffs, fits free-tier TPM cleanly because narrative prompts are ~500 tokens. Cleared the 37-article backlog this session.
- **Historical TTP backfill script (`scripts/backfill_tactical_analysis.py`)**: same shape for `ttp_extract`, with two important differences born of pain: (a) per-call retry budget instead of lifetime — a TPM streak can no longer exhaust a single global counter and starve every subsequent article; (b) always sleeps `--sleep` between articles regardless of outcome, so a give-up path can't burn through the queue at hundreds per second. The 70B model is too token-heavy for free-tier TPM under contention with the live pipeline (~1.8K tokens/call saturates a per-key minute window), so override `LLM_MODEL=llama-3.1-8b-instant` when running this script. Cleared the 366-article backlog this session.

### Operations
- **1129 articles enriched this session** across three backfills: 366 TTPs (`tactical_analysis`), 37 CVE narratives, 446 summaries (730 of 1180 stragglers remain — the 8B model couldn't generate non-empty JSON for articles with thin body content; left for another session).
- **Day's token usage 683K of ~1M envelope (~68%)** — TTP backfill alone burned ~480K via 8B model. Multi-key rotation is account-scoped on Groq free tier (not per-key) — when account TPM caps out, all 3 keys 429 in the same second. Smaller prompts dodge this; pacing helps.

### Testing
- 89 tests on the changed modules (`test_top_stories`, `test_briefing_generator`, `test_llm_client`) — patched `_TOP_STORIES_MODEL` rather than `LLM_MODEL` in the success-generation test, and added implicit coverage for the new `model` kwarg via the existing call paths.

## 2026-04-23 — Free-Tier Groq Capitalization (CVE narratives · TTP extractor · LLM ATT&CK fallback · tokens tile)

Context: per-caller Groq usage (landed 2026-04-22) showed we were using <5% of the free daily token budget. This session capitalises on the unused headroom with three LLM-backed enrichments and swaps the dashboard's always-$0 cost tile for live token throughput.

### Added
- **CVE exploitation narratives (`modules/cve_narrative.py`)**: new LLM pass that turns raw NVD metadata (CVSS, vector, CWE, affected products, EPSS percentile) into a 3-sentence analyst narrative — *what an attacker practically does, who's exposed, how urgent*. Gated at CVSS ≥ 8.0 OR EPSS percentile ≥ 0.80 so only actually-dangerous CVEs burn tokens. Cached by CVE ID (descriptions are immutable per NVD), so each CVE is paid for exactly once across its lifetime. Envelope at 20–30 new high-sev CVEs/day × ~1.5K tokens ≈ 30–45K tokens/day before cache hits. Wired into `threatdigest_main.main` between EPSS enrichment and ATT&CK tagging. `caller="cve_narrative"`.
- **Deep TTP extractor (`modules/ttp_extractor.py`)**: second LLM pass over the *full scraped body* of high-signal incident articles, producing structured `tactical_analysis = {summary, ttps[], persistence[], lateral_movement[], impact[], confidence}`. Today's classifier and ATT&CK tagger only see title + short summary, so the tactical gold (exact persistence mechanisms, lateral-movement paths, C2 behaviours) that lives in body paragraphs was being discarded. Gated on `is_cyber_attack` + body ≥ 500 chars; cache-first by article hash; hard-capped at `TTP_EXTRACT_MAX_CALLS=40`/run so one noisy feed day can't exhaust the budget. `caller="ttp_extract"`.
- **LLM fallback for ATT&CK under-tagging (`modules/attack_tagger.py`)**: opt-in (`LLM_ATTACK_FALLBACK=true`) pass that escalates cyber-incident articles the regex pass tagged with fewer than `LLM_ATTACK_FALLBACK_MIN=2` techniques to the LLM, which returns up to 5 canonical ATT&CK IDs. Regex-validated (`Txxxx` / `Txxxx.yyy`) before merge so hallucinated IDs are dropped; each LLM-sourced technique is stamped `source="llm"` for transparency. Cache-first by article hash; budget-capped by `LLM_ATTACK_FALLBACK_MAX_CALLS=100`/run. `caller="attack_llm"`.
- **AI tokens tile on dashboard (`threatwatch.html`)**: bottom-left footer tile switched from "API COST TODAY" (which read `pipeline_summary.api_cost_today`, an Anthropic-SDK-only figure that was always $0.00 on this deployment) to "AI TOKENS TODAY" sourced from `/api/groq-usage`. Shows total prompt + completion tokens for the day, human-formatted (12.3K / 1.45M); hover tooltip breaks down total calls, avg tokens/call, and prompt vs completion split.

### Testing
- 1270 tests / 95%+ coverage — up from 1233. +37 tests across the three new LLM paths: cache hit/miss, gating thresholds (CVSS/EPSS, body length, is_cyber_attack), budget caps, malformed-JSON / invalid-ID / hallucinated-ID defences, merge semantics (regex ∪ LLM, no duplicates, tactic deduping), and caller tagging so the Groq usage tracker attributes spend correctly.

## 2026-04-22 — Pipeline Runtime + AI Decoupling + ATT&CK on Actors

### Fixed
- **Briefing staleness alarm (`modules/briefing_generator.py`)**: `generated_at` was stamped at function entry rather than at save time. Under Groq rate-limit backoff the LLM call could block for 100+ min, so every saved briefing looked hours old the moment it hit disk and tripped the staleness alarm immediately. Now stamped at save time across all three paths (fresh generation, cache hit, regional).
- **Abandoned feed_health entries (`serve_threatwatch.build_health`)**: feeds disabled in config lingered in `feed_health.json` with their final error status and inflated the `/api/health` error count. Now only counts entries checked within the last 24h.

### Performance
- **LLM circuit breaker + timeout tightening (`modules/llm_client.py`)**: runs were taking 3–5+ hours each on the VPS vs. the intended 10-min interval. Root cause: `urllib3.Retry(status_forcelist=[500,502,503,504])` with default `respect_retry_after_header=True` — a single Groq 503 with a long `Retry-After` cascaded into hours of blocked time across retries × keys × per-run LLM calls. Removed urllib3 retry entirely; added explicit 5xx/Timeout/ConnectionError handling that rotates keys without retry; tightened default timeout 90s → 30s (`LLM_TIMEOUT`); added a process-local circuit breaker (`LLM_CIRCUIT_THRESHOLD=3`) that short-circuits remaining calls after N consecutive failures in a run. Verified: one run went 341 min → 45 min.

### Added
- **Decoupled AI enrichment architecture**: the four AI tiers (global briefing, regional digests, top stories, article summaries) now live in `modules/ai_enrichment.py` and run out-of-band via `scripts/run_ai_enrichment.py`. `scripts/run_pipeline.py` invokes AI every `AI_ENRICHMENT_EVERY` pipeline ticks (default 3 = ~30 min) independent of the 10-min fetch loop. `AI_ENRICHMENT_INLINE=0` (new default) skips inline AI; set to `1` to restore legacy inline behaviour. Fetch pipeline is no longer blocked by Groq rate limits.
- **ATT&CK on actor profiles (`modules/actor_profiler.py`)**: every profile now carries `observed_techniques: [{id, count}]` and `observed_tactics: [{name, count}]` aggregated from articles mentioning the actor. Refreshed every run for both new and existing profiles, grounding the LLM-generated `signature_ttps` narrative in data-driven evidence.
- **ATT&CK on dashboard (`threatwatch.html`)**: actor spotlight cards render the top 3 observed techniques as compact accent-coloured pills (`T1566×3 T1486×2`); hover tooltip appends observed tactics. Falls back to the LLM-described `signature_ttps` line when observed data isn't present so the card stays functional for older profiles. 9/17 live actors now carry evidence-backed TTPs.
- **Briefing threat-level webhook alerts (`modules/webhook.py`)**: `dispatch_briefing_alert(briefing)` fires when the global briefing's `threat_level` is at or above `WEBHOOK_BRIEFING_MIN_LEVEL` (default ELEVATED). Deduplicated by level-change + `WEBHOOK_BRIEFING_COOLDOWN_HOURS` (default 6h) so the same level doesn't re-alert every tick. Slack/Discord payload uses level-appropriate emojis and includes up to 3 priority actions; generic JSON payload carries the full structured fields. Wired into the AI enrichment orchestrator.
- **Groq LLM usage tracker (`modules/groq_usage.py`)**: the existing `cost_tracker.py` only worked for Anthropic SDK responses — the bulk of pipeline LLM traffic (classification, briefing, regional, top stories, summaries, actor profiles, cluster synth) was invisible. New tracker reads OpenAI-style `response.usage.prompt_tokens` / `completion_tokens` and aggregates per-day / per-key / per-caller in `data/state/groq_usage.json`. Keys are masked to an 8-char prefix + ellipsis so the secret never hits disk; last 90 days retained. Callers tagged: `classify`, `briefing`, `regional`, `top_stories`, `summaries`, `actor_profile`, `cluster_synth`. Exposed via new endpoint `GET /api/groq-usage` which returns today's totals, per-key breakdown, per-caller breakdown, and 7-day daily totals.

### Fixed
- **Actor profiler schema mismatch (hotfix)**: `actor_profiler.extract_actors_from_articles` was reading `t.get("id")` but `attack_tagger` emits `{technique_id, technique_name, tactic}` dicts — caused zero `observed_techniques` on the live API despite 535/2184 articles carrying ATT&CK tags. Now reads `technique_id` first, falls back to `id` for forward-compat. Regression-locked with a test that uses the real attack_tagger schema.

### Performance
- **Fetch concurrency + URL-resolver timeouts**: `MAX_FEED_FETCH_THREADS` and `MAX_SCRAPER_THREADS` both 8 → 16 (env-tunable). URL resolver HEAD timeout 5s → 3s (`URL_RESOLVER_REDIRECT_TIMEOUT`), GET 8s → 5s (`URL_RESOLVER_CANONICAL_TIMEOUT`). News-site timeouts were inherited from LLM-call defaults and too generous for the actual latency profile.

### Testing
- 1233 tests / 95% coverage (modules/) — up from 1141 / 92%. +92 tests across 15 modules, concentrated on the new circuit-breaker paths, decoupling orchestrator, actor ATT&CK aggregation, briefing alert thresholds + cooldown, Groq-usage per-key/per-caller aggregation, and long-standing coverage gaps in `feed_health`, `trend_detector`, `briefing_health`, `nvd_fetcher`, and `newsapi_fetcher`.

## 2026-04-21 — CTI Platform + Security Hardening + SQLite Migration

### Added
- Campaign persistence (`modules/campaign_tracker.py`): stable UUIDs keyed by `(entity_type, entity_name)` that survive across pipeline reclusters. Persists to `data/output/campaigns.json`. Tracks `first_observed` (ever-earliest), `last_observed`, `total_observed_articles`, `status` (active, dormant, archived by 14d and 90d thresholds), capped at 500 hashes per campaign. Atomic tmp+rename writes.
- Victim-sector taxonomy (`modules/victim_tagger.py`): 14-sector regex taxonomy (Healthcare, Finance, Government, Education, Energy, Technology, Telecom, Retail, Manufacturing, Transportation, Media, Legal, Critical Infrastructure, Hospitality). Writes `victim_sectors` list onto each article.
- IOC extraction (`modules/ioc_extractor.py`): IPv4, IPv6, domains, URLs, SHA256, SHA1, MD5, emails with defang handling (`[.]`, `hxxp://`, `[at]`), TLD allowlist, placeholder-IP blocklist. Writes `iocs` dict on each article.
- CVE write-back (`modules/incident_correlator.annotate_articles_with_cves`): extracts CVE IDs to `cve_ids` on every article so the dashboard can facet by CVE.
- New API endpoints: `GET /api/cve/<ID>`, `GET /api/campaigns[?status=...]`, `GET /api/campaign/<uuid>`.
- `modules/date_utils.py`: single source of truth for feed/article date parsing. Consolidates four divergent parsers across `feed_fetcher`, `output_writer`, `darkweb_monitor`, `incident_correlator`.
- `modules/safe_http.py`: process-wide SSRF guard that monkey-patches urllib3 `create_connection` to re-validate hostnames at connect time, closing the DNS-rebind TOCTOU in `is_safe_url`.
- Frontend pills on each article card: CVE pill (clickable, filters feed), IOC pill (type-grouped tooltip), sector pill (clickable, filters feed), story pill (prefers campaign `first_observed` so long-running campaigns keep their true age across 7-day corpus rotations).
- Nightly Docker volume backup (`scripts/backup_volume.sh`), rotates to 7 archives in `~/backups/threatwatch/`. Cron at 03:15 UTC.
- `scripts/cleanup.py` applies `ARCHIVE_RETENTION_DAYS` (default 30) to `hourly/` and `daily/` subdirs; previously retained 365 days of archive snapshots.
- STIX 2.1: confidence field, relationship objects, `object_refs` including indicator IDs.
- RSS: `<guid>`, `<category>`, `atom:link rel="self"` per item.
- Briefing staleness detection (`modules/briefing_health.py`): never-raising freshness check compares `generated_at` against `BRIEFING_STALE_HOURS` (default 3h). Surfaces via pipeline ERROR log, self-healing flag file (`data/state/briefing_stale.flag`), and new `briefing_stale` / `briefing_age_hours` fields on `/api/health`.
- SQLite migration complete: Phase 1 shadow-write (commit `a433720`), Phase 2 env-gated read adapter (commit `4ffd1d7`), Phase 3 prune cutoff + `READ_FROM_SQLITE=1` active in production. JSON files kept as fallback for parity-check.
- Per-feed signal score, `/api/since` cursor, `/api/feedback` endpoint, offsite volume backup.
- `scripts/backfill_summaries.py`: one-shot script to generate AI summaries for articles that predate the pipeline's summarization window.

### Security
- Fix `javascript:` URI XSS via feed `<link>`: `safeHref()` allowlist (`http:`, `https:`, `mailto:`).
- Rate limiter reads `X-Real-IP` only when TCP peer is a configured trusted proxy (`TRUSTED_PROXIES` env var, default `127.0.0.1,::1`). Prevents shared rate-limit bucket for all nginx-proxied users.
- Thread-safety fixes on `serve_threatwatch._cache`, `url_resolver._CACHE` (FIFO eviction), `feed_health.record_fetch`, `hybrid_classifier._escalation_count`.
- Pipeline container healthcheck now tests `stats.json` mtime under 25 minutes (was: file-exists-only).
- Bearer token auth for POST `/api/watchlist` (`WATCHLIST_TOKEN` env var).
- HSTS header, CSP Google Fonts allowlist, 64KB POST limit on `/api/watchlist`.
- Sanitized error responses — no internal paths or exceptions exposed.
- CORS restricted on `/api/health` and `/api/watchlist`; `CORS_ORIGIN` env var for opt-in.
- Rate limiter IP eviction prevents unbounded memory growth.
- Thread-safe atomic writes for watchlist persistence (tmp+rename).
- Remove `CSP script-src 'unsafe-inline'` via `data-click-action` delegation.

### Fixed
- `output_writer._parse_pub_date` no longer falls back to `datetime.now()` on parse failure.
- `darkweb_monitor._parse_date` format-slice bug replaced with shared `date_utils.parse_datetime`.
- `deduplicate_articles` no longer mutates caller article dicts.
- Incident correlator persists all clusters (not just top 15) and emits `first_seen` + `article_hashes` per cluster.
- Tag darkweb victim posts from title only; expanded benign-domain list.
- Sector false-positives on darkweb posts; benign-domain IOC filter.
- `/api/feedback` fail-closed; scheduler heartbeat.

### Changed
- `_MAX_SUMMARIES_PER_RUN` raised from 30 to 150 (env-overridable `MAX_SUMMARIES_PER_RUN`).
- SSR payload strips `article_hashes` from per-cluster objects after annotation.
- `depends_on: service_started` (not `service_healthy`) for the server container.
- Strip `full_content` from SSR payload.
- `/api/articles` always returns envelope `{articles, total, offset, limit, has_more}`.
- Coverage threshold raised from 65% to 75%; 765 tests total.

## 2026-03-19 — UI Redesign + Multi-Theme System

### Added
- Full UI redesign with professional modern look
- 5 switchable themes: Nightwatch (dark), Parchment (light), Solarized, Arctic, Phosphor (CRT)
- Theme dropdown picker with localStorage persistence
- IBM Plex Mono + Space Grotesk typography
- Phosphor CRT scanline overlay effect

## 2026-03-18 — NewsAPI + Briefing Hardening

### Added
- NewsAPI integration with rate limiting (free tier: 100 req/day)
- Three-layer region accuracy fix (content inference, ISO-2 codes, multi-region collapse)
- Non-Commercial License

### Fixed
- Briefing accuracy (max_tokens, cache key, schema validation)
- Crash bug in briefing generator

## 2026-03-15 — Features Expansion

### Added
- Brand Watch tab — monitor custom brand keywords
- Tech Watch tab — 244 vendors across 18 categories
- APT Tracker with actor intelligence grid
- IOC Tracker with ThreatFox integration
- STIX 2.1 export endpoint
- Webhook alerts (Slack and generic)
- Watchlist monitor module
- Feed search in left panel
- IOC export functionality
- NEW/APT CRITICAL badges

## 2026-03-14 — Architecture + CI/CD

### Added
- `/api/health` endpoint
- `scripts/run_pipeline.py` scheduler
- Docker Compose two-service deployment
- GitHub Actions CI (lint, test, coverage, pip-audit, Docker build)
- 243 initial tests

### Security
- SSRF protection on URL fetching
- Security headers (CSP, X-Frame-Options, nosniff)
- XSS escaping on SSR data injection
- Docker non-root user
- Rate limiting (120 req/min per IP)
