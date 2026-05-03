<div align="center">

# ThreatWatch

**AI-powered cyber threat intelligence platform — zero cost**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: Non-Commercial](https://img.shields.io/badge/license-Non--Commercial-orange.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Zero Cost](https://img.shields.io/badge/cost-%240%2Fmonth-brightgreen)]()
[![AI Powered](https://img.shields.io/badge/AI-intelligence--briefing-8B5CF6?logo=openai&logoColor=white)]()
[![Feeds](https://img.shields.io/badge/feeds-155+-blue)]()
[![GitHub Stars](https://img.shields.io/github/stars/AuvaLabs/threatwatch?style=social)](https://github.com/AuvaLabs/threatwatch)

**[Live Demo](https://threatwatch.auvalabs.com)**

AI-powered threat intelligence platform that aggregates 155+ RSS feeds, dark web sources, and NewsAPI — classifies, deduplicates, and generates analyst-grade intelligence digests with AI-curated top stories, incident clustering, threat actor profiles, and actionable priority recommendations with source citations. Runs entirely free using Groq's API free tier. Self-hosted, zero-cost infrastructure.

[Features](#features) · [Quick start](#quick-start) · [Configuration](#configuration) · [Architecture](#architecture) · [API](#api-endpoints) · [Integrations](docs/INTEGRATIONS.md) · [Contributing](#contributing)

</div>

---

## Dashboard

![ThreatWatch Dashboard](docs/preview.gif)

---

## Features

### Collection
- **155+ RSS feeds** — security blogs, vendor advisories, CERTs worldwide, Google News, Bing News
- **NewsAPI integration** — additional security news with rate-limited fetching (100 req/day free tier)
- **Dark web monitoring** — ThreatFox IOCs, ransomware victim tracking (ransomware.live), active C2 server IPs
- **10-minute pipeline** cycle with automatic GitHub Pages deployment every 15 minutes
- **8-thread parallel fetching** — processes all feeds in seconds
- Rolling **7-day window** with merge across pipeline runs

### AI Intelligence (Groq-powered, zero cost)
- **Intelligence Digest** — hourly AI-generated threat landscape summary with trending threats, vulnerability spotlight, sector impact, and priority actions — every finding links back to source articles
- **Top Stories** — AI picks the 5-8 most significant incidents from all articles, with significance ratings (CRITICAL/HIGH/MODERATE)
- **Article Summaries** — structured AI summaries (what/who/impact) for articles missing descriptions
- **Incident Clustering** — auto-groups related articles by CVE, threat actor, or organization with AI-synthesized cluster narratives
- **Threat Actor Profiles** — cached AI-generated profiles for detected actors (origin, TTPs, target sectors)
- **AI Classification Escalation** — low-confidence articles get reclassified by Groq LLM
- **Smart key rotation** — multiple API keys with automatic 429 failover for sustainable free-tier usage

### Classification
- **24 threat categories**: Ransomware, Zero-Day, APT/Nation-State, DDoS, Supply Chain, Phishing, Malware, Data Breach, Vulnerability, Threat Research & Analysis, Detection & Response, and more
- **Hybrid classifier** — regex-first (zero cost), AI escalation for ambiguous articles
- **75+ threat actors and malware families** (APT28, LockBit, Lazarus Group, Scattered Spider, Salt Typhoon, etc.)
- **Content-aware region attribution** — infers geographic region from article title with attacker-vs-target disambiguation
- ISO-3166 country code mapping for ransomware victim data (DE → Europe, JP → APAC, BR → LATAM, etc.)
- **15 industry sectors**
- **Noise filtering** — product announcements, job listings, funding rounds, training content auto-excluded
- **Quality score 92/100** — comprehensive audit covering classification, dedup, regions, timeliness

### Deduplication
- Fuzzy matching with a **word-shingle inverted index** (24x faster than naive pairwise)
- CVE-aware deduplication — articles reporting different CVEs are never merged
- Cross-source region merge, collapsing to Global when an article spans 3+ regions

### Dashboard
- Server-side rendered, **loads in under a second**
- **Single HTML file** — no build step, no framework, no JavaScript bundle; IBM Plex Mono + Space Grotesk typography
- **9 focused tabs**: Intel Brief, Breach, Exploits, Malware, Dark Web, Ransomware, APT Tracker, Brands, Tech
- Each tab filters the left-panel live feed — one click to see all matching articles
- EXPLOITS merges zero-days + vulnerabilities + patches (one analyst workflow)
- MALWARE includes phishing + supply chain attacks (attack methods)
- **Brand Watch tab** — monitor specific brands/organisations; selecting a brand filters the left panel
- **Tech Watch tab** — 244 technology vendors across 18 categories; selecting a vendor filters the left panel
- Watch filter banner in the left panel shows the active brand/vendor filter at a glance
- **Ransomware Tracker** — victim posts from ransomware.live + ransomware news, grouped by threat actor
- **APT Tracker** — actor intelligence grid with drilldown into news articles
- **4 center-panel sections**: Intelligence Digest (AI), Headlines (AI-curated), Active Threat Actors (with AI profile TTPs), Sector Impact
- Region filter buttons with article counts — context banner when filtered
- Article detail view with IOC extraction (CVEs, IPs, hashes, domains)
- Watchlist preferences saved to localStorage; self-hosted installs can persist keywords server-side
- **AI Intelligence Digest** — 5-section briefing: What Happened (24h narrative with source links), What To Do (specific actions), Earlier This Week (catch-up), Outlook (forecast). **Regional digests** for NA, EMEA, APAC — auto-switches when region selected
- **TL;DR lead-story hero** — LLM-written single-sentence headline above each briefing; falls back to a regex-distilled first sentence when the model field is absent
- **Escalation banner** — when threat level shifts vs the prior briefing, an arrow + colour-coded "Escalated MODERATE → ELEVATED" row surfaces the change with the assessment basis as the why
- **Headlines panel** — AI-curated 5-8 most significant incidents from last 72 hours, with cluster-related article badges
- **Trending Threats panel** — spike detection (today vs 14d baseline) plus a 7-day top-mentioned leaderboard for ransomware groups, APTs, CVEs, and attack types
- **CISA KEV badges** — articles referencing CVEs in the CISA Known Exploited Vulnerabilities catalog get an unmistakable "act now" pill, with darker shading for ransomware-linked entries
- **"X new since HH:MM UTC" pill** — returning-reader counter at the top of the feed; persistent NEW badge on each article published since your last visit, dismissible with one click
- **Share buttons** — copy-link on each article (`?article=<hash>` permalinks) and a one-click share that copies the briefing's level + headline + dashboard URL ready to paste into Slack/Teams/Telegram
- Auto-generated statistical briefing as fallback (zero cost, no API key needed)
- **5 switchable themes** — Nightwatch (dark brass), Parchment (light cream), Solarized (default), Arctic (clean blue), Phosphor (retro CRT)
- Both live URLs displayed in the page footer

### Region accuracy
- **Content-based inference** — scans article title for country/demonym mentions and assigns the correct region, overriding feed locale labels (a UK article from a US-localized Google feed gets tagged Europe, not US)
- **ISO-2 code support** — ransomware.live victim data uses 2-letter codes (DE, FR, GB); fully mapped
- **Multi-region collapse** — articles appearing in 4+ regional feeds collapse to Global instead of producing long joined tags like `Canada,India,Singapore,UAE,US`

### Integration
- RSS feed output for feed readers and SIEMs
- STIX 2.1 bundle export for Microsoft Sentinel, Splunk, Elastic, OpenCTI, MISP
- JSON API for programmatic access (CORS enabled)
- **Telegram dispatcher** — built-in bot that posts CRITICAL briefing escalations and per-CVE CISA KEV alerts to a channel, dedup-aware so you only hear what you need to hear
- **Slack / Discord / generic webhooks** — built-in dispatcher with level-change + cooldown deduplication
- See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) for copy-paste recipes (Microsoft Teams via Azure Logic Apps, /api/since alert flows, RSS in Outlook/Feedly)

---

## Quick start

### Docker Compose (recommended)

```bash
git clone https://github.com/AuvaLabs/threatwatch.git
cd threatwatch

# Optional: configure environment
cp .env.example .env   # edit as needed

# Start everything
docker compose up -d
```

The pipeline runs immediately on startup, then every 10 minutes. Dashboard is at **http://localhost:8098**.

### Manual setup

```bash
git clone https://github.com/AuvaLabs/threatwatch.git
cd threatwatch

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

mkdir -p data/output/hourly data/output/daily \
         data/state/ai_cache \
         data/logs/run_logs data/logs/summaries

# Run the pipeline once
python threatdigest_main.py

# Start the dashboard server
python serve_threatwatch.py
```

For automatic refresh, add a cron job:

```cron
*/10 * * * * cd /path/to/ThreatWatch && /path/to/venv/bin/python threatdigest_main.py >> data/logs/cron.log 2>&1
```

---

## Configuration

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8098` | Dashboard server port |
| `SITE_DOMAIN` | `localhost:8098` | Domain for RSS feed links |
| `FEED_CUTOFF_DAYS` | `7` | Rolling window for articles |

### Optional: NewsAPI

Sign up at [newsapi.org](https://newsapi.org) for a free API key (100 requests/day). ThreatWatch automatically rate-limits to stay within the free tier.

| Variable | Default | Description |
|---|---|---|
| `NEWSAPI_KEY` | _(empty)_ | newsapi.org API key |
| `NEWSAPI_INTERVAL` | `1800` | Seconds between NewsAPI calls (default 30 min) |

### Optional: AI intelligence platform

ThreatWatch works without any API keys. To enable the full AI platform (intelligence digest, top stories, article summaries, incident clustering, actor profiles, and AI classification), configure any OpenAI-compatible LLM provider:

| Variable | Default | Description |
|---|---|---|
| `LLM_API_KEY` | _(empty)_ | API key for your LLM provider |
| `LLM_API_KEYS` | _(empty)_ | Comma-separated keys for round-robin rotation |
| `LLM_BASE_URL` | `https://api.groq.com/openai/v1` | API base URL |
| `LLM_MODEL` | `llama-3.3-70b-versatile` | Model name |
| `LLM_PROVIDER` | `auto` | `auto`, `openai`, `anthropic`, `ollama` |

**Recommended free setup** — [Groq](https://console.groq.com) provides free API access (500K tokens/day per key):

```env
LLM_API_KEY=gsk_your_key_here
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_MODEL=llama-3.3-70b-versatile

# Optional: multiple keys for higher throughput (round-robin with 429 failover)
LLM_API_KEYS=gsk_key1,gsk_key2,gsk_key3
```

Also works with OpenAI, Together, Ollama (local), Mistral, DeepSeek, and any OpenAI-compatible API. Smart key rotation automatically fails over on rate limits (429).

### Optional: premium tiers for the daily briefing

The global daily briefing prompt (~7-8K tokens) exceeds Groq free-tier per-request 6K TPM, which forces the briefing to run on the lighter `llama-3.1-8b-instant` model with a clipped 1200-token output. Two optional layers can give it real headroom — either or both can be enabled:

| Variable | Tier | Default | Description |
|---|---|---|---|
| `FEATHERLESS_API_KEY` | 1 (paid) | _(empty)_ | Featherless.ai key (`rc_...`) — primary briefing path, 32K context |
| `FEATHERLESS_BASE_URL` | 1 | `https://api.featherless.ai/v1` | OpenAI-compatible endpoint |
| `FEATHERLESS_MODEL` | 1 | `deepseek-ai/DeepSeek-V3.2` | Featherless model id (also: `kimi-k2`, `glm46-357b`) |
| `FEATHERLESS_TIMEOUT` | 1 | `60` | Per-request seconds |
| `CLAUDE_BRIDGE_URL` | 2 (subscription) | _(empty)_ | Local OpenAI-compatible shim wrapping the `claude` CLI (e.g. `http://host-gateway:8400/v1`) |
| `CLAUDE_BRIDGE_MODEL` | 2 | `sonnet` | Claude model id (`sonnet`, `opus`, `haiku`) |
| `CLAUDE_BRIDGE_TIMEOUT` | 2 | `300` | Per-request seconds |

The briefing tries tier 1 → tier 2 → Groq+8B in order. Each tier is independent and a failure (429, 5xx, timeout) drops straight to the next tier without retrying. Regional briefings, top stories, classifier, and the other AI features keep using Groq directly — only the global briefing opts into the cascade.

### Feed configuration

Feeds are defined in YAML files under `config/`:

| File | Description |
|---|---|
| `feeds_native.yaml` | Security blogs, vendor advisories, CERTs |
| `feeds_google.yaml` | Google News search queries (regional + threat-specific) |
| `feeds_bing.yaml` | Bing News search queries |

Edit these files to add or remove feeds. No restart needed — changes apply on the next pipeline run.

---

## Architecture

**Pipeline** (`threatdigest_main.py`): Feeds → Fetch → Deduplicate → Scrape → Classify (regex + AI) → Region Inference → NVD/EPSS/ATT&CK → Output → AI Briefing → Top Stories → Summaries → Clustering → Actor Profiles

**Server** (`serve_threatwatch.py`): Python HTTP server with SSR, ETag caching, gzip, CORS

**Frontend** (`threatwatch.html`): Single HTML file. No build step, no framework.

**Storage**: Flat JSON files. No database, no Redis, no message queue.

### Project structure

```
threatdigest_main.py         # Pipeline orchestrator
serve_threatwatch.py         # HTTP server with SSR
threatwatch.html             # Dashboard UI (single file)
modules/
  ├── feed_loader.py         # YAML feed config parser
  ├── feed_fetcher.py        # Parallel RSS fetcher
  ├── deduplicator.py        # Fuzzy dedup (word-shingle index)
  ├── article_scraper.py     # Full-text extraction
  ├── keyword_classifier.py  # Zero-cost regex classifier (24 categories)
  ├── hybrid_classifier.py   # Keyword + AI escalation classifier
  ├── region_inferrer.py     # Content-based region attribution
  ├── llm_client.py          # Shared Groq/OpenAI client (multi-key rotation)
  ├── briefing_generator.py  # AI briefing, top stories, article summaries
  ├── incident_correlator.py # Entity-based incident clustering + AI synthesis
  ├── actor_profiler.py      # Threat actor profile generation + caching
  ├── nvd_fetcher.py         # NVD CVE enrichment
  ├── epss_enricher.py       # EPSS exploit probability scores
  ├── attack_tagger.py       # MITRE ATT&CK technique tagging
  ├── trend_detector.py      # Trending threat spike detection
  ├── darkweb_monitor.py     # Dark web intel aggregation
  ├── newsapi_fetcher.py     # NewsAPI security news feed
  ├── output_writer.py       # JSON/RSS output
  ├── config.py              # Global configuration
  └── ...
config/
  ├── feeds_native.yaml      # Security blogs & CERTs
  ├── feeds_google.yaml      # Google News feeds
  └── feeds_bing.yaml        # Bing News feeds
scripts/
  ├── validate_feeds.py      # Feed health checker
  └── cleanup.py             # Data cleanup utility
data/
  ├── output/                # JSON + RSS output files
  ├── state/                 # Pipeline state & cache
  └── logs/                  # Run logs & summaries
tests/                       # Test suite (80%+ coverage)
docker-compose.yml           # Two-service deployment
Dockerfile                   # Python 3.11-slim based
```

---

## API endpoints

> **Building an integration?** See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md)
> for copy-paste recipes — daily briefing → Microsoft Teams via Azure Logic App,
> incremental IOC alerts to Slack/Teams, STIX 2.1 ingest into Sentinel/Splunk/Elastic,
> RSS in Outlook/Feedly, plus the built-in webhook dispatcher.

The server runs on port **8098** by default:

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard (server-side rendered HTML) |
| `GET` | `/api/articles` | All articles as JSON array |
| `GET` | `/api/articles?offset=0&limit=20` | Paginated articles |
| `GET` | `/api/briefing` | AI intelligence digest with source citations |
| `GET` | `/api/briefing/na` | North America regional digest |
| `GET` | `/api/briefing/emea` | EMEA regional digest |
| `GET` | `/api/briefing/apac` | Asia-Pacific regional digest |
| `GET` | `/api/top-stories` | AI-curated top stories (5-8 per cycle) |
| `GET` | `/api/clusters` | Incident correlation clusters |
| `GET` | `/api/actor-profiles` | Threat actor profiles |
| `GET` | `/api/trends` | Trending threat spike data |
| `GET` | `/api/stats` | Pipeline run statistics |
| `GET` | `/api/health` | Server health + feed status |
| `GET` | `/api/stix` | STIX 2.1 bundle export |
| `GET` | `/api/watchlist` | Watchlist config + vendor list |
| `POST` | `/api/watchlist` | Update watchlist (self-hosted) |
| `GET` | `/api/rss` | RSS feed (XML) |

All JSON endpoints support CORS, ETag conditional requests, and gzip compression.

<details>
<summary>Example: paginated articles response</summary>

```json
{
  "articles": [
    {
      "title": "LockBit ransomware targets healthcare sector",
      "translated_title": "LockBit ransomware targets healthcare sector",
      "link": "https://example.com/article",
      "published": "2026-03-21T10:00:00+00:00",
      "category": "Ransomware",
      "confidence": 95,
      "is_cyber_attack": true,
      "summary": "Brief summary of the article...",
      "region": "US",
      "assetTags": ["CrowdStrike"],
      "related_articles": []
    }
  ],
  "total": 150,
  "offset": 0,
  "limit": 20,
  "has_more": true
}
```

</details>

<details>
<summary>Example: health response</summary>

```json
{
  "status": "ok",
  "uptime_s": 3600,
  "last_run_at": "2026-03-21T10:00:00+00:00",
  "articles_total": 150,
  "articles_cyber": 120,
  "api_cost_today_usd": 0.05,
  "feed_health": {"ok": 140, "dead": 5, "slow": 10},
  "generated_at": "2026-03-21T10:05:00+00:00"
}
```

</details>

---

## Running tests

```bash
pip install -r requirements.txt
pytest tests/ -v
pytest tests/ --cov=modules --cov-report=term-missing
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details. The short version:

1. Fork the repo
2. Create a branch (`git checkout -b feat/your-feature`)
3. Write tests, keep coverage above 80%
4. Follow existing code style
5. Run `pytest tests/ -v`
6. Commit using [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, etc.)
7. Open a PR

### Good first contributions

- New RSS feed sources or CERTs
- Threat actor or malware family patterns
- Dashboard visualisations
- STIX/TAXII export
- Webhook or notification integrations

---

## Security

See [SECURITY.md](SECURITY.md) for the security policy and how to report vulnerabilities responsibly.

---

## License

ThreatWatch is **open source for non-commercial use**.

See [LICENSE](LICENSE) for the full terms or contact [nicholai.me](https://nicholai.me).

---

<div align="center">

by [nicholai.me](https://nicholai.me) · [AuvaLabs](https://github.com/AuvaLabs)

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-FFDD00?logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/nicholai.me)

</div>
