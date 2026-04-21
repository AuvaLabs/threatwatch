# Changelog

All notable changes to ThreatWatch are documented here.

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
