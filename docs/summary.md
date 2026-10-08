# ThreatWatch project summary

ThreatWatch is a self-hosted cyber intelligence operations platform built by [nicholai.me](https://nicholai.me) at [AuvaLabs](https://github.com/AuvaLabs). It turns public reporting into a source-linked threat-state and decision ledger, correlated threats, qualified hunt packages, and operational reports.

## Product surfaces

- **Today** leads with material state changes and deterministic patch, hunt, investigate, and monitor decisions.
- **Ledger** preserves stable CVE and actor records, evidence, uncertainty, decisions, and revision history.
- **Threats** presents CVE and named-actor clusters with persistent campaign history.
- **Hunts** separates qualified packages from developing leads and includes observable provenance, ATT&CK behavior, vulnerability context, telemetry, queries, sources, and limitations.
- **Reports** combines the current briefing, metrics, decisions, and source citations into a portable operating picture.
- **Automation** exposes OpenAPI, STIX 2.1, RSS, health, and integration contracts.
- **Sources** preserves the full bounded and searchable evidence library.

## Intelligence pipeline

- Parallel collection from native security feeds, Google News, Bing News, NewsAPI, NVD, ThreatFox, ransomware.live, CISA KEV, and custom watchlists.
- Seven-day corpus with exact and fuzzy deduplication, canonical URLs, normalized dates, and SQLite primary persistence.
- Regex-first classification with optional LLM escalation, region inference, sector tags, CVE extraction, EPSS, KEV, ATT&CK tagging, TTP extraction, and article-aware IOC validation.
- Briefing and summary generation through a primary OpenAI-compatible route and two independent fallbacks.
- Incident correlation on shared CVEs and named threat actors, followed by persistent campaign tracking.
- Evidence-gated hunt generation from every report in a cluster, with optional cached ThreatFox and URLhaus corroboration.
- Versioned threat-state generation with deterministic decisions and unchanged-run stability.
- Feed, artifact, pipeline, and briefing freshness exposed through health endpoints.

## Hunt qualification

A hunt requires independent reporting or an authoritative structured-provider match, an actionable observable, mapped ATT&CK behavior, and a readiness score of at least 60. Publisher domains, source links, advisory references, weak domains without threat context, and version-like IPv4 values are suppressed. Candidates that do not pass remain developing leads.

See [HUNTS.md](HUNTS.md) for the full contract and rebuild runbook.

## Technology

- Python 3.11 HTTP server and pipeline.
- Preact and TypeScript frontend built with Vite.
- Docker Compose services for `pipeline` and `server` with one persistent data volume.
- SQLite primary storage plus atomic JSON artifacts and fallback reads.
- Strict security headers, bounded APIs, request rate limiting, SSRF protection, safe external URLs, and no scraped full-content exposure in operational APIs.
- 1,492 backend tests and 52 frontend tests at the 2026-10-08 ledger release. Frontend statement coverage was 96.02 percent.

## Core architecture

```text
Sources
  -> fetch and normalize
  -> deduplicate and classify
  -> CVE, EPSS, KEV, ATT&CK, TTP, and IOC enrichment
  -> SQLite plus atomic JSON outputs
  -> briefings and source-linked reports
  -> CVE and actor clustering
  -> cached IOC corroboration
  -> qualified hunts and developing leads
  -> versioned threat-state and decision ledger
  -> versioned API
  -> Preact analyst workspace
```

Important implementation files:

```text
threatdigest_main.py          Pipeline orchestrator
serve_threatwatch.py          HTTP server and public API
frontend/src/                 Typed analyst workspace
modules/operations.py         Operational decision queue
modules/incident_correlator.py Correlated CVE and actor evidence
modules/ioc_extractor.py      Text extraction and defang handling
modules/ioc_quality.py        Article-aware observable validation
modules/ioc_enrichment.py     Cached provider corroboration
modules/hunt_engine.py        Qualification and analyst package generation
modules/threat_ledger.py      Public record state, decisions, and revision history
modules/db.py                 SQLite persistence and enrichment cache
scripts/rebuild_hunts.py      Safe hunt artifact backfill
scripts/rebuild_ledger.py     History-preserving ledger backfill
```

## Stable operational APIs

- `GET /api/v1/articles`
- `GET /api/v1/articles/{id}`
- `GET /api/v1/briefings/latest`
- `GET /api/v1/incidents`
- `GET /api/v1/hunts`
- `GET /api/v1/hunts/{id}`
- `GET /api/v1/ledger`
- `GET /api/v1/ledger/changes`
- `GET /api/v1/ledger/{id}`
- `GET /api/v1/operations/summary`
- `GET /api/v1/sources`
- `GET /api/v1/health`
- `GET /api/v1/health/ai`
- `GET /api/v1/health/feeds`
- `GET /api/v1/openapi.json`

## Deployment

- Repository: `https://github.com/AuvaLabs/threatwatch`
- Production: `https://threatwatch.auvalabs.com`
- Production checkout: `/home/deploy/threatwatch` on the `auvalabs` VPS.
- Persistent data: Docker volume `threatwatch-data` mounted at `/app/data`.

Typical deployment from the maintained workspace:

```bash
git push origin main
ssh auvalabs 'cd ~/threatwatch && git pull --ff-only origin main && docker compose build pipeline server && docker compose up -d --no-deps pipeline server'
```

After hunt changes, rebuild the current artifact and validate both containers:

```bash
ssh auvalabs 'docker exec threatwatch-pipeline python scripts/rebuild_hunts.py'
ssh auvalabs 'docker exec threatwatch-pipeline python scripts/rebuild_ledger.py'
ssh auvalabs 'cd ~/threatwatch && docker compose ps'
```

Last updated: 2026-10-08
