# ThreatWatch Breach Anatomy

Breach Anatomy converts fragmented public reporting into versioned incident records. It is deterministic by default and does not require a model provider.

## Correlation contract

An article must contain an incident signal and a conservatively extracted victim organization. Articles are grouped only when they also share a compatible event type, fall inside the bounded reporting window, and have a second correlation signal such as shared title context, an affected product, an ATT&CK technique, or structured victim metadata.

Publisher names do not automatically prove independence. Exact syndicated headlines share one source family. A record needs at least two independent source families to become `corroborated`. Single-source candidates remain `developing` and cannot enter Today.

## Claim states

Every claim has one or more valid source article identifiers.

- `confirmed`: supported by authoritative evidence
- `reported`: stated by one or more sources
- `assessed`: an analyst or structured tactical inference
- `disputed`: incompatible sourced claims remain unresolved
- `unknown`: an explicit evidence gap

Unsupported source references are rejected. A record without a confirmed claim cannot receive a critical score.

## Scoring

The score is bounded from 0 to 100 and combines independent corroboration, operational impact, technical detail, recency, detection value, and sector relevance. Developing single-source records are capped below the Today threshold. Today requires a score of at least 60 and `corroborated` state.

## Public API

```text
GET /api/v1/incidents/v2
GET /api/v1/incidents/v2/changes
GET /api/v1/incidents/v2/{id}
```

The collection response omits detailed claims, sources, observables, and history. Retrieve the detail route before taking action. Scraped full article content never crosses these endpoints.

## Artifact and fallback

The pipeline writes `data/output/incidents-v2.json` atomically. The server rebuilds a missing, invalid, or stale artifact in memory from the public article corpus. It does not make provider calls and does not write from an HTTP request.

## Accuracy gates

Before release:

1. A multi-source non-CVE fixture must produce one incident record.
2. Unrelated reporting about the same organization must remain separate.
3. Syndication must not inflate the independent-source count.
4. Every claim must resolve to a source in the same record.
5. Existing CVE and KEV priority ordering must remain unchanged.
6. Null, missing, stale, and corrupt artifact paths must fail safely.
7. A live-corpus audit must review every record that crosses the Today threshold.
