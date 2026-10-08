# ThreatWatch public threat-state ledger

The ledger is ThreatWatch's durable public intelligence layer. It converts a rolling stream of reports into stable CVE and actor records that explain what changed, which decision follows, and which evidence supports that decision.

## Product boundary

ThreatWatch does not ask users to upload asset inventories, technology stacks, customer lists, or other organizational data. It does not claim that a named organization is exposed.

The public service publishes vendor-neutral threat records. A consumer can retrieve those records through the API and match them against private telemetry or inventory inside its own trusted environment.

## Record lifecycle

1. Articles are normalized, classified, and enriched with structured vulnerability and behavior context.
2. Reports are grouped by exact CVE or named threat actor.
3. Qualified hunt data is attached when the hunt evidence gate passes.
4. The ledger derives current activity, exploitation, evidence, hunt, and remediation states.
5. A deterministic decision selects patch, hunt, investigate, or monitor and records its rationale.
6. Meaningful state changes increment the record version and append a revision event.
7. An unchanged rebuild preserves the version, timestamp, and history.
8. A record that leaves the rolling reporting window is retained as `not_recent` instead of disappearing.

Initial tracking events and state changes include the source article identifiers that supported the assessment at that time. Each record retains up to 30 changes. The global change register retains up to 500 changes, and the ledger retains up to 1,000 records.

## Decision rules

| Decision | Deterministic basis |
|---|---|
| `patch` | The CVE is present in CISA Known Exploited Vulnerabilities data. |
| `hunt` | The related hunt package passed the evidence gate. |
| `investigate` | Exploitation is reported, EPSS is elevated, or independently reported actor activity requires validation. |
| `monitor` | Available evidence does not yet justify a stronger action. |

The decision is a triage recommendation, not proof of exposure. Remediation text is included only when an authoritative structured source provides it. Missing versions, products, or confirmation remain explicit unknowns.

## API

### List records

```http
GET /api/v1/ledger?activity=active&type=cve&action=patch&q=gateway&offset=0&limit=50
```

Supported filters:

- `activity`: `active` or `not_recent`
- `type`: `cve` or `actor`
- `action`: `patch`, `hunt`, `investigate`, or `monitor`
- `q`: case-insensitive text match across entity, title, summary, and affected products
- `offset`: non-negative integer
- `limit`: 1 to 200

The response includes global decision counts, the current bounded change register, the filtered total, and the requested record page.

### Read one record

```http
GET /api/v1/ledger/threat-8d4471112a1fb906
```

Record identifiers are derived from entity type and normalized entity name. They remain stable across rebuilds.

### Poll changes

```http
GET /api/v1/ledger/changes
```

This endpoint is suitable for dashboards, notification flows, and downstream private matching. Use `ETag` and `If-None-Match` to avoid downloading unchanged data.

## Rebuild and recovery

Rebuild the current artifact from SQLite, with JSON fallback:

```bash
python scripts/rebuild_ledger.py
```

The script reads the previous ledger before publishing the replacement. Atomic output prevents partial reads. Running it twice against unchanged inputs must produce zero new run changes on the second pass.

In Docker:

```bash
docker exec threatwatch-pipeline python scripts/rebuild_ledger.py
```

The server also reconstructs a missing or stale ledger from current articles, clusters, and hunts. Pipeline and server fallback paths use the same deterministic builder.

## AI integration

The ledger schema is intentionally usable without an LLM. Optional AI can improve article summaries or cluster synthesis upstream, but it does not control record identity, state transitions, evidence counts, decision rules, or history.

Future assistants can consume the public endpoints to explain a record, compare revisions, or draft a private query. They should cite record sources, preserve uncertainty, and never upgrade a public technology mention into an organizational exposure claim.
