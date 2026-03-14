# ThreatWatch — Project Summary

**ThreatWatch** is a self-hosted, real-time cyber threat intelligence dashboard built by [Nicholai](https://nicholai.me) at AuvaLabs.

## Features

- **Live Threat Intelligence Feed** — left panel streaming curated threat news, filtered by type (breach, ransomware, APT, phishing, malware, zero-day, vuln, dark web)
- **Threat Intelligence Briefing** — AI-generated executive summary, key incidents, active threat actors, and sector impact analysis
- **IOC Tracker** — dedicated panel for ThreatFox/abuse.ch IOC data, grouped by malware family, filterable by IP / Hash / Domain / URL / CVE; copy-to-clipboard chips
- **APT Tracker** — actor intelligence grid tracking Lazarus Group, Volt Typhoon, APT28/Sandworm, APT29/Cozy Bear, APT41, Charming Kitten, Scattered Spider, Salt Typhoon, Kimsuky and more; click any actor to cross-filter the news feed
- **Region filtering** — GLOBAL / NA / EMEA / MENA / APAC / LATAM
- **Server-side rendering** — zero-latency page load via embedded JSON data
- **Auto-refresh** — polls for new data every 2 minutes

## Tech Stack

- Python HTTP server (`serve_threatwatch.py`) — port 8098
- Single-file frontend (`threatwatch.html`) — vanilla JS, no framework
- Data pipeline: `threatdigest_main.py`, `modules/darkweb_monitor.py`, `modules/feed_fetcher.py`
- ThreatFox / abuse.ch integration for IOC feeds
- 190+ threat intelligence RSS/API sources

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
```

Last updated: 2026-03-14
