# ThreatWatch project summary

ThreatWatch is a self-hosted cyber intelligence operations platform built by [nicholai.me](https://nicholai.me) at [AuvaLabs](https://github.com/AuvaLabs). It turns public reporting into a source-linked threat-state and decision ledger, correlated threats, qualified hunt packages, and operational reports.

## Product surfaces

- **Today** is a compact daily desk for the three most important incidents, material changes, and deterministic decisions.
- **Incidents** presents corroborated, evidence-linked Breach Anatomy records with focused filters.
- **Hunts** separates qualified packages from developing leads and includes observable provenance, ATT&CK behavior, vulnerability context, telemetry, queries, sources, and limitations.
- **Investigations** provides a private local casebook with portable import and export.
- **Ledger** preserves every material state change and its reason with focused paging.
- **Reports** combines the current briefing, metrics, decisions, and source citations into a portable operating picture.
- **API** exposes OpenAPI, STIX 2.1, RSS, health, and grouped integration contracts.
- **Status** makes pipeline freshness, artifact ownership, deployment identity, and recovery state visible.
- **Sources** preserves the full bounded and searchable evidence library.

## Intelligence pipeline

- Parallel collection from native security feeds, Google News, Bing News, NewsAPI, NVD, ransomware.live, CISA KEV, and custom watchlists, with optional authenticated ThreatFox lookups.
- Seven-day corpus with exact and fuzzy deduplication, canonical URLs, normalized dates, and SQLite primary persistence.
- Regex-first classification with optional LLM escalation, region inference, sector tags, CVE extraction, EPSS, KEV, ATT&CK tagging, TTP extraction, and article-aware IOC validation.
- Briefing and summary generation through a primary OpenAI-compatible route and two independent fallbacks.
- Incident correlation on shared CVEs and named threat actors, followed by persistent campaign tracking.
- Victim-centred incident records with source-bound claims, source-family deduplication, explicit uncertainty, and deterministic scoring.
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
- 1,657 backend tests and 58 frontend tests at the 2026-11-07 repository audit. Both suites remain above the required 80 percent coverage floor.

## Verified operational snapshot

The 2026-11-07 production review verified the following state for release
`ced0d048a0eb3ae12fa8c0b58de6839ae7b6d990`:

- Both production containers were healthy, the public workspace routes returned successful responses, and `/api/v1/health` reported an operational service.
- A controlled source validation completed with all 135 configured feeds healthy. The Orca source uses publisher-scoped discovery because its former native RSS endpoint redirects to itself.
- ThreatFox uses its authenticated API when a key is available. The key remains outside Git in `.secrets/threatfox.env`, and evidence links use stable malware identifiers instead of guessed slugs.
- ThreatFox and URLhaus results remain corroborating evidence. They do not independently qualify a hunt without the required observable, behavior, and readiness evidence.
- The corpus, SQLite store, hunt artifacts, incident artifacts, ledger artifacts, and source-linked reports passed consistency checks. The offsite backup status included a successful independent restore proof.
- The backend suite passed all 1,657 tests. The frontend suite passed all 58 tests, and its production build completed successfully.

Run `scripts/validate_feeds.py` while the scheduled pipeline writer is idle. The
validator and pipeline currently use a process-local state lock, so overlapping
them can race when publishing feed-health state even when collection itself is
healthy.

## Core architecture

```text
Sources
  -> fetch and normalize
  -> deduplicate and classify
  -> CVE, EPSS, KEV, ATT&CK, TTP, and IOC enrichment
  -> SQLite plus atomic JSON outputs
  -> briefings and source-linked reports
  -> CVE and actor clustering
  -> victim-centred incident records and material changes
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
modules/incident_records.py    Versioned Breach Anatomy records
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
- `GET /api/v1/clusters`
- `GET /api/v2/incidents`
- `GET /api/v2/incidents/changes`
- `GET /api/v2/incidents/{id}`
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
- `GET /api/v2/openapi.json`

## Deployment

- Repository: `https://github.com/AuvaLabs/threatwatch`
- Production: `https://threatwatch.auvalabs.com`
- Production checkout: `/home/deploy/threatwatch` on the `auvalabs` VPS.
- Persistent data: Docker volume `threatwatch-data` mounted at `/app/data`.

Typical deployment from the maintained workspace:

```bash
git push origin main
ssh auvalabs 'cd ~/threatwatch && git pull --ff-only origin main && bash scripts/deploy.sh'
```

The deployment script fails closed on a dirty checkout or unhealthy baseline,
creates a restore-verified backup, embeds the release SHA and build time, polls
the versioned health endpoint, checks corpus continuity and the primary API
routes, and restores the previous container images on failure.

`scripts/backup_volume.sh` briefly pauses the pipeline writer for a consistent
SQLite and WAL snapshot. It writes a SHA-256 sidecar, restores the archive into
an isolated temporary directory, checks every SQLite database and JSON file,
and publishes the result through `/api/v1/health`. The pull-based offsite
verifier repeats the restore proof on separate storage and publishes that
independent result without placing destination credentials on the VPS.

After hunt changes, rebuild the current artifact and validate both containers:

```bash
ssh auvalabs 'docker exec threatwatch-pipeline python scripts/rebuild_hunts.py'
ssh auvalabs 'docker exec threatwatch-pipeline python scripts/rebuild_ledger.py'
ssh auvalabs 'cd ~/threatwatch && docker compose ps'
```

Last updated: 2026-11-07
