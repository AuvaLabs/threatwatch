# ThreatWatch hunt packages

ThreatWatch treats a hunt package as an evidence-backed analyst starting point. An extracted IOC or an ATT&CK tag on one article is not enough.

## Qualification contract

The hunt engine accepts CVE and named-actor clusters from the incident correlator. It evaluates all articles referenced by the cluster's full `article_hashes` list, not only the ten-item UI preview.

A candidate becomes `qualified` only when all of these conditions hold:

- At least two reports from two independent publishers, or one authoritative structured-provider match.
- At least one actionable observable. Confirmed domains and URLs qualify; context-validated IP addresses and cryptographic hashes can qualify when reported by one technical source.
- At least one ATT&CK technique supported by the correlated reporting.
- A readiness score of at least 60.

Everything else remains a `lead`. Leads stay visible for analyst awareness, but the UI disables package copying until the evidence gate passes.

## Observable quality and provenance

`modules/ioc_quality.py` validates stored observables against article context. It suppresses:

- The article, canonical, feed, and publisher domains.
- Domains or URLs mentioned without IOC, command-and-control, phishing, payload, beacon, callback, or other explicit threat context.
- Public-looking IPv4 values used next to version markers.
- Duplicate observables that differ only by case.

Each retained observable includes its type, value, disposition, confidence, source articles, publisher identities, and nearby context. Dispositions are:

- `confirmed`: corroborated by multiple independent publishers, a structured feed, or an authoritative provider match.
- `reported`: actionable evidence from one technical report that still requires local validation.

Provider response bodies remain in the SQLite cache. The public API exposes only provider name, status, and confidence.

## Package contents

Every record returned by `GET /api/v1/hunts` contains:

- Stable hunt ID, entity, status, confidence, readiness, first-seen time, report count, and publisher count.
- A hunt hypothesis and evidence-basis statements.
- Source-linked observables with provenance.
- ATT&CK techniques and tactics.
- CVE, CISA KEV, maximum CVSS, and maximum EPSS context when present.
- Required telemetry, KQL starter queries, analyst triage steps, false-positive checks, and explicit limitations.
- A portable Markdown representation in `markdown`.

The API never includes scraped `full_content`.

## API

```bash
# All qualified packages and developing leads
curl -s http://localhost:8098/api/v1/hunts | jq

# Qualified packages only
curl -s "http://localhost:8098/api/v1/hunts?status=qualified" | jq

# One package
HUNT_ID="hunt-d7b34ff35f6ecbc0"
curl -s "http://localhost:8098/api/v1/hunts/${HUNT_ID}" | jq
```

An unsupported `status` returns HTTP 400. A syntactically valid but missing hunt ID returns HTTP 404.

## Optional provider corroboration

Local qualification works without external credentials. Set these variables to enable cached provider lookups:

```env
THREATFOX_AUTH_KEY=
URLHAUS_AUTH_KEY=
HUNT_ENRICHMENT_MAX_LOOKUPS=40
HUNT_ENRICHMENT_TTL_HOURS=24
```

ThreatFox supports exact IOC searches for IPs, domains, URLs, and hashes. URLhaus is queried only for complete URLs. The pipeline stores provider results in the `observable_enrichments` SQLite table and does not make provider calls from API requests.

Failed providers do not prevent local package generation. Attempts are capped per cycle, expired cache entries are refreshed, and credentials are never stored in the database or API response.

## Operations

The pipeline rebuilds `data/output/hunts.json` after incident clustering. The server uses that artifact when it is at least as new as `clusters.json`; otherwise it rebuilds a deterministic local response without provider calls.

Run a safe backfill against the current corpus and cluster artifact:

```bash
python scripts/rebuild_hunts.py
```

In Docker:

```bash
docker exec threatwatch-pipeline python scripts/rebuild_hunts.py
```

The script reads SQLite first and falls back to `daily_latest.json` when the database is empty. It does not rewrite source articles.

## Analyst boundary

Starter queries are intentionally conservative and currently target Microsoft Defender KQL schemas. Validate table availability, field names, retention, tenant scope, and query cost before use. A qualified package is not proof of compromise and must not directly trigger blocking, isolation, or containment.
