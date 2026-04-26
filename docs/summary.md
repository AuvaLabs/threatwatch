# ThreatWatch — Project Summary

**ThreatWatch** is a zero-cost, self-hosted cyber threat intelligence platform built by [nicholai.me](https://nicholai.me) at [AuvaLabs](https://github.com/AuvaLabs).

## Features

- **Live Threat Intelligence Feed** — 164 RSS/API sources, filtered by category (breach, ransomware, APT, phishing, malware, zero-day, vuln, dark web) and region; confidence score badge with hover tooltip explaining classification drivers
- **Threat Intelligence Briefing** — zero-cost rule-based briefing + optional AI-generated executive summary via any OpenAI-compatible LLM provider (default: Groq free tier); LLM-written `headline` field renders as a TL;DR hero above the narrative
- **Escalation banner** — when threat level shifts vs the prior briefing, an arrow + colour-coded "Escalated/De-escalated from X to Y" row surfaces the change with the assessment basis as the why
- **CISA KEV ingestion** — articles referencing CVEs in the CISA Known Exploited Vulnerabilities catalog get distinctive pills (darker for ransomware-linked entries) and feed the briefing prompt as authoritative "actively exploited" signal
- **Trending Threats panel** — spike detection (today vs 14d baseline) plus a 7-day top-mentioned leaderboard for ransomware groups, APTs, CVEs, and attack types
- **Campaign Tracker** — stable UUIDs for persistent incident campaigns with active/dormant/archived status
- **Incident Clustering** — auto-groups related articles by CVE, threat actor, or organization with AI-synthesized narratives
- **Ransomware Tracker** — group intelligence grid showing victim posts (ransomware.live) and news per group
- **APT Tracker** — actor intelligence grid tracking major nation-state threat actors with AI-generated profiles
- **IOC Tracker** — ThreatFox IOC feed with hash, IP, domain, and URL indicators
- **IOC Extraction** — per-article IPv4, IPv6, domains, URLs, SHA256/SHA1/MD5, emails with defang handling
- **Brand Watch** — monitor specific brands/organisations across the intel feed
- **Tech Watch** — 244 technology vendors across 18 categories; custom tech keywords for any vendor not in the list
- **NewsAPI integration** — additional security news (100 req/day free tier)
- **Victim Sector Tagging** — 14-sector regex taxonomy (Healthcare, Finance, Government, etc.)
- **Region filtering** — GLOBAL / NA / EMEA / MENA / APAC / LATAM with content-based inference
- **Server-side rendering** — zero-latency page load via embedded JSON data
- **Auto-refresh** — polls for new data every 2 minutes
- **"X new since HH:MM UTC" pill** — returning-reader counter; persistent NEW badge on each article published since your last visit, dismissible with one click
- **Share buttons** — copy-link on each article (`?article=<hash>` permalinks) and a one-click share that copies the briefing's level + headline + dashboard URL ready to paste into Slack/Teams/Telegram
- **5 switchable themes** — Nightwatch (dark brass), Parchment (light cream), Solarized, Arctic (clean blue), Phosphor (retro CRT with scanline overlay)
- **SQLite storage** — Phase 3 complete with READ_FROM_SQLITE=1 in production; JSON files kept as fallback
- **Briefing staleness detection** — automatic health monitoring with `/api/health` alarm

## Tech Stack

- Python HTTP server (`serve_threatwatch.py`) — port 8098
- Single-file frontend (`threatwatch.html`) — vanilla JS, no framework, no build step; IBM Plex Mono + Space Grotesk typography
- Data pipeline: `threatdigest_main.py` orchestrating 20+ modules
- Docker Compose two-service deployment (pipeline + server)
- SQLite database (primary) + flat JSON (fallback)
- 1329 tests, 95% coverage (modules/)
- Decoupled AI enrichment: fetch pipeline (10-min) and AI pipeline (30-min) run on independent schedules; LLM circuit breaker + explicit timeout caps cascade failures
- ATT&CK-grounded actor profiles: observed techniques/tactics aggregated from articles mentioning the actor, refreshed every run
- Briefing threat-level webhook alerts with level-change + 6h cooldown deduplication (Slack/Discord/generic)
- **Telegram dispatcher** — built-in bot posts CRITICAL briefing escalations + per-CVE CISA KEV alerts to a channel with permanent dedup; default threshold tuned for "what I need to know" cadence (~1-2 messages/day on average)
- **STIX 2.1 export** at `GET /api/stix` for SIEM/SOAR ingest (Microsoft Sentinel, Splunk, Elastic, OpenCTI, MISP)
- Groq LLM usage tracker: per-key and per-caller token accounting, exposed via `GET /api/groq-usage`
- Integrations guide at [docs/INTEGRATIONS.md](INTEGRATIONS.md) — copy-paste recipes for Microsoft Teams via Azure Logic Apps, Telegram bot setup, RSS in Outlook/Feedly

## Architecture

```
Browser → serve_threatwatch.py (SSR injection)
                ↓
        threatwatch.html (HTML + CSS + JS)
                ↓
        /api/articles  /api/briefing  /api/stats  /api/campaigns  /api/cve/<ID>
                ↓
        SQLite DB (data/output/threatwatch.db) + JSON fallback
                ↓
        threatdigest_main.py (pipeline)
        ├── feed_fetcher.py        (164 RSS feeds, 8-thread parallel)
        ├── newsapi_fetcher.py     (NewsAPI security news)
        ├── darkweb_monitor.py     (ThreatFox, ransomware.live)
        ├── deduplicator.py        (fuzzy word-shingle dedup)
        ├── region_inferrer.py     (content-based region attribution)
        ├── keyword_classifier.py  (24 threat categories)
        ├── hybrid_classifier.py   (keyword + AI escalation)
        ├── briefing_generator.py  (AI briefing, any LLM provider)
        ├── incident_correlator.py (entity-based clustering + AI synthesis)
        ├── campaign_tracker.py    (persistent campaign tracking)
        ├── ioc_extractor.py       (IOC extraction per article)
        ├── victim_tagger.py       (14-sector taxonomy)
        ├── actor_profiler.py      (threat actor profiles)
        ├── date_utils.py          (unified date parsing)
        └── safe_http.py           (SSRF guard)
```

## Links

- **Live Demo**: https://threatwatch.auvalabs.com
- **Repository**: https://github.com/AuvaLabs/threatwatch

Last updated: 2026-04-22
