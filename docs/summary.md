# ThreatWatch — Project Summary

**ThreatWatch** is a zero-cost, self-hosted cyber threat intelligence platform built by [nicholai.me](https://nicholai.me) at [AuvaLabs](https://github.com/AuvaLabs).

## Features

- **Live Threat Intelligence Feed** — left panel streaming curated threat news from 155+ RSS/API sources, filtered by category (breach, ransomware, APT, phishing, malware, zero-day, vuln, dark web) and region
- **Threat Intelligence Briefing** — zero-cost rule-based briefing + optional AI-generated executive summary via any OpenAI-compatible LLM provider
- **Ransomware Tracker** — group intelligence grid showing victim posts (ransomware.live) and news per group; filter by ALL / VICTIMS / NEWS; click any group to drilldown
- **APT Tracker** — actor intelligence grid tracking Lazarus Group, Volt Typhoon, APT28/Sandworm, APT29/Cozy Bear, APT41, Charming Kitten, Scattered Spider, Salt Typhoon, Kimsuky and more
- **IOC Tracker** — ThreatFox IOC feed with hash, IP, domain, and URL indicators
- **Brand Watch** — monitor specific brands/organisations across the intel feed
- **Tech Watch** — 244 technology vendors across 18 categories; select vendors to highlight matching articles
- **NewsAPI integration** — additional security news with rate-limited fetching (100 req/day free tier)
- **Region filtering** — GLOBAL / NA / EMEA / MENA / APAC / LATAM with content-based inference
- **Server-side rendering** — zero-latency page load via embedded JSON data
- **Auto-refresh** — polls for new data every 2 minutes

## Tech Stack

- Python HTTP server (`serve_threatwatch.py`) — port 8098
- Single-file frontend (`threatwatch.html`) — vanilla JS, no framework, no build step
- Data pipeline: `threatdigest_main.py` orchestrating 12+ modules
- Docker Compose two-service deployment (pipeline + server)
- Flat JSON storage — no database, no Redis

## Architecture

```
Browser → serve_threatwatch.py (SSR injection)
                ↓
        threatwatch.html (HTML + CSS + JS)
                ↓
        /api/articles  /api/briefing  /api/stats
                ↓
        data/output/daily_latest.json
                ↓
        threatdigest_main.py (pipeline)
        ├── feed_fetcher.py      (155+ RSS feeds, 8-thread parallel)
        ├── newsapi_fetcher.py   (NewsAPI security news)
        ├── darkweb_monitor.py   (ThreatFox, ransomware.live, C2 IPs)
        ├── deduplicator.py      (fuzzy word-shingle dedup)
        ├── region_inferrer.py   (content-based region attribution)
        ├── keyword_classifier.py (22 threat categories)
        └── briefing_generator.py (AI briefing, any LLM provider)
```

## Links

- **Live Demo**: https://threatwatch.auvalabs.com
- **GitHub Pages**: https://auvalabs.github.io/ThreatWatch/
- **Repository**: https://github.com/AuvaLabs/ThreatWatch

Last updated: 2026-03-19
