<div align="center">

# ThreatWatch

**Zero-cost, self-hosted cyber threat intelligence platform**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Zero Cost](https://img.shields.io/badge/cost-%240%2Fmonth-brightgreen)]()
[![Feeds](https://img.shields.io/badge/feeds-155+-blue)]()
[![GitHub Stars](https://img.shields.io/github/stars/AuvaLabs/threatwatch?style=social)](https://github.com/AuvaLabs/threatwatch)

**[Live Demo](https://threatwatch.auvalabs.com)** · **[GitHub Pages](https://auvalabs.github.io/threatwatch/)**

Aggregates threat intelligence from 155+ RSS feeds and dark web sources, classifies articles by category, and serves a live dashboard. Runs on your own infrastructure. No API keys required.

[Features](#features) · [Quick start](#quick-start) · [Dashboard](#dashboard) · [Architecture](#architecture) · [API](#api-endpoints) · [Contributing](#contributing)

</div>

---

## Dashboard preview

![ThreatWatch Dashboard](docs/preview.gif)

---

## Features

### Collection
- 155+ RSS feeds (security blogs, Google News, Bing News, CERTs worldwide)
- Dark web monitoring (ThreatFox IOCs, ransomware victim tracking, C2 server IPs)
- 10-minute refresh cycle with automatic GitHub Pages deployment
- 8-thread parallel fetching, processes all feeds in seconds
- Rolling 7-day window with merge across pipeline runs

### Classification
- 22 threat categories: ransomware, zero-day, APT, DDoS, supply chain, etc.
- 75+ threat actors and malware families (APT28, LockBit, Lazarus Group, etc.)
- 80+ countries with geo-attribution
- 15 industry sectors
- Noise filtering: product announcements, job listings, funding rounds auto-excluded
- Regex-based keyword classifier, no API calls needed

### Deduplication
- Fuzzy matching with a word-shingle inverted index
- 24x faster than naive pairwise comparison
- Cross-region merge with content-first region attribution

### Dashboard
- Server-side rendered, loads in under a second
- Single HTML file, no build step, no framework
- Auto-generated threat intelligence briefing (Normal mode)
- Optional AI-powered briefing (any LLM provider — toggle in UI)
- Key incidents panel with direct article links
- Threat actor spotlight and sector impact panels with drilldown
- Region filters (Global, NA, EMEA, MENA, APAC, LATAM) — content-aware
- Category filters (Ransomware, Breach, DDoS, APT, etc.)
- Article detail view with IOC extraction (CVEs, IPs, hashes, domains)
- Ransomware Tracker tab: victim posts from ransomware.live + ransomware news, grouped by threat actor
- APT Tracker tab: actor intelligence grid with drilldown into news articles
- Brand Watch tab: monitor specific brands/organisations — articles grouped by brand, "No recent news" fallback per brand
- Tech Watch tab: 244 technology vendors across 18 categories (Endpoint, Network, Cloud, IAM, OT/ICS, etc.) — articles grouped by vendor, sorted by coverage
- Watchlist preferences saved to localStorage; self-hosted installs can persist custom keywords server-side (`WATCHLIST_WRITE_ENABLED=true`)
- Light and dark theme

### Integration
- RSS feed output for feed readers and SIEMs
- JSON API for programmatic access
- CORS enabled for embedding in other dashboards

---

## Quick start

### Docker Compose (recommended)

```bash
git clone https://github.com/AuvaLabs/threatwatch.git
cd threatwatch

# Create .env file (optional, works without it)
cp .env.example .env

# Start everything
docker compose up -d
```

The pipeline runs immediately on startup, then every 10 minutes. Dashboard is at **http://localhost:8098**.

### Manual setup

```bash
# Clone
git clone https://github.com/AuvaLabs/threatwatch.git
cd threatwatch

# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create data directories
mkdir -p data/output/hourly data/output/daily \
         data/state/ai_cache \
         data/logs/run_logs data/logs/summaries

# Run the pipeline
python threatdigest_main.py

# Start the dashboard server
python serve_threatwatch.py
```

For automatic refresh, add a cron job:

```cron
*/10 * * * * cd /path/to/threatwatch && /path/to/venv/bin/python threatdigest_main.py >> data/logs/cron.log 2>&1
```

---

## Configuration

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8098` | Dashboard server port |
| `SITE_DOMAIN` | `localhost:8098` | Domain for RSS feed links |
| `FEED_CUTOFF_DAYS` | `7` | Rolling window for articles |

### Optional: AI-powered briefing

ThreatWatch works without any API keys. To enable AI-powered briefings, configure any OpenAI-compatible LLM provider:

| Variable | Default | Description |
|---|---|---|
| `LLM_API_KEY` | _(empty)_ | API key for your LLM provider |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | API base URL |
| `LLM_MODEL` | `gpt-4o-mini` | Model name |
| `LLM_PROVIDER` | `auto` | `auto`, `openai`, `anthropic`, `ollama` |

Works with OpenAI, Groq, Together, Ollama (free/local), Mistral, DeepSeek, and any OpenAI-compatible API.

### Feed configuration

Feeds are defined in YAML files under `config/`:

| File | Description |
|---|---|
| `feeds_native.yaml` | Security blogs, vendor advisories, CERTs |
| `feeds_google.yaml` | Google News search queries |
| `feeds_bing.yaml` | Bing News search queries |

Edit these files to add or remove feeds. No restart needed. Changes apply on the next pipeline run.

---

## Architecture

**Pipeline** (`threatdigest_main.py`): Feeds > Fetch > Deduplicate > Scrape > Classify > AI Briefing (optional) > Output

**Server** (`serve_threatwatch.py`): Python HTTP server with SSR, ETag caching, gzip, CORS

**Frontend** (`threatwatch.html`): Single HTML file. No build step, no framework.

**Storage**: Flat JSON files. No database, no Redis, no message queue.

### Project structure

```
threatdigest_main.py     # Pipeline orchestrator
serve_threatwatch.py     # HTTP server with SSR
threatwatch.html         # Dashboard UI (single file)
modules/
  ├── feed_loader.py     # YAML feed config parser
  ├── feed_fetcher.py    # Parallel RSS fetcher
  ├── deduplicator.py    # Fuzzy dedup (word-shingle index)
  ├── article_scraper.py # Full-text extraction
  ├── keyword_classifier.py  # Zero-cost regex classifier
  ├── briefing_generator.py  # AI briefing (any LLM provider)
  ├── darkweb_monitor.py     # Dark web intel aggregation
  ├── output_writer.py   # JSON/RSS output
  ├── config.py          # Global configuration
  └── ...
config/
  ├── feeds_native.yaml  # Security blogs & CERTs
  ├── feeds_google.yaml  # Google News feeds
  └── feeds_bing.yaml    # Bing News feeds
scripts/
  ├── deploy_gh_pages.py # GitHub Pages static deploy
  ├── validate_feeds.py  # Feed health checker
  ├── cleanup.py         # Data cleanup utility
  └── weekly_digest.py   # Weekly summary generator
data/
  ├── output/            # JSON + RSS output files
  ├── state/             # Pipeline state & cache
  └── logs/              # Run logs & summaries
tests/                   # Test suite
docker-compose.yml       # Two-service deployment
Dockerfile               # Python 3.11-slim based
```

---

## API endpoints

The server runs on port **8098** by default:

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard (server-side rendered HTML) |
| `GET` | `/api/articles` | All articles as JSON |
| `GET` | `/api/articles?offset=0&limit=20` | Paginated articles |
| `GET` | `/api/briefing` | Threat intelligence briefing |
| `GET` | `/api/stats` | Pipeline run statistics |
| `GET` | `/api/rss` | RSS feed (XML) |

All JSON endpoints support CORS, ETag conditional requests, and gzip compression.

---

## Running tests

```bash
# Install dev dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run with coverage
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

- New RSS feed sources
- Threat actor or malware family patterns
- Dashboard visualizations
- STIX/TAXII export
- Webhook or notification integrations

---

## Security

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

---

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## License

[MIT](LICENSE) — free for personal and commercial use.

---

<div align="center">

by [Nicholai Imbong](https://github.com/nicholaiimbong) · [AuvaLabs](https://github.com/AuvaLabs)

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-FFDD00?logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/nicholaiimbong)

</div>
