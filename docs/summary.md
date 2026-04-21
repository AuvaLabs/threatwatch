# ThreatWatch — Project Summary

**ThreatWatch** is a zero-cost, self-hosted cyber threat intelligence platform built by [nicholai.me](https://nicholai.me) at [AuvaLabs](https://github.com/AuvaLabs).

## Features

- **Live Threat Intelligence Feed** — 155+ RSS/API sources, filtered by category (breach, ransomware, APT, phishing, malware, zero-day, vuln, dark web) and region; confidence score badge with hover tooltip explaining classification drivers
- **Threat Intelligence Briefing** — zero-cost rule-based briefing + optional AI-generated executive summary via any OpenAI-compatible LLM provider (default: Groq free tier)
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
- **5 switchable themes** — Nightwatch (dark brass), Parchment (light cream), Solarized, Arctic (clean blue), Phosphor (retro CRT with scanline overlay)
- **SQLite storage** — Phase 3 complete with READ_FROM_SQLITE=1 in production; JSON files kept as fallback
- **Briefing staleness detection** — automatic health monitoring with `/api/health` alarm

## Tech Stack

- Python HTTP server (`serve_threatwatch.py`) — port 8098
- Single-file frontend (`threatwatch.html`) — vanilla JS, no framework, no build step; IBM Plex Mono + Space Grotesk typography
- Data pipeline: `threatdigest_main.py` orchestrating 20+ modules
- Docker Compose two-service deployment (pipeline + server)
- SQLite database (primary) + flat JSON (fallback)

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
        ├── feed_fetcher.py        (155+ RSS feeds, 8-thread parallel)
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
- **GitHub Pages**: https://auvalabs.github.io/threatwatch/
- **Repository**: https://github.com/AuvaLabs/threatwatch

Last updated: 2026-04-21
