<div align="center">

# 🛡️ ThreatWatch

**Zero-cost, self-hosted cyber threat intelligence platform**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Zero Cost](https://img.shields.io/badge/cost-%240%2Fmonth-brightgreen)]()
[![Feeds](https://img.shields.io/badge/feeds-142-blue)]()

Monitor the global threat landscape from your own infrastructure — no API keys, no subscriptions, no third-party dependencies.

[Features](#-features) · [Quick Start](#-quick-start) · [Dashboard](#-dashboard) · [Architecture](#-architecture) · [API](#-api-endpoints) · [Contributing](#-contributing)

</div>

---

## 📸 Screenshots

<!-- Add screenshots of the dashboard here -->
<!-- ![Dashboard](docs/screenshots/dashboard.png) -->
<!-- ![Drilldown](docs/screenshots/drilldown.png) -->

_Screenshots coming soon._

---

## ✨ Features

### Intelligence Collection
- **142 RSS feeds** — security blogs, Google News, Bing News, CERTs worldwide
- **30-minute refresh cycle** — always up to date
- **8-thread parallel fetching** — processes all feeds in seconds
- **Rolling 7-day window** with merge across pipeline runs

### Classification & Enrichment
- **22 threat categories** — ransomware, zero-day, APT, DDoS, supply chain, and more
- **75+ threat actors & malware families** — APT28, LockBit, Lazarus Group, and others
- **80+ countries** with geo-attribution
- **15 industry sectors** under attack
- **Zero-cost keyword classifier** — regex-based, no API calls required

### Deduplication
- **Fuzzy matching** using word-shingle inverted index
- **24x faster** than naive pairwise comparison
- Catches near-duplicate articles across different sources

### Dashboard
- **Server-side rendered** — instant load (<1 second)
- **Single HTML file** — no build step, no framework, no node_modules
- **Threat Intelligence Briefing** — auto-generated narrative summary
- **Key Incidents** panel with direct article links
- **Threat Actor Spotlight** with drilldown filtering
- **Sector Impact Analysis** with drilldown filtering
- **Threat Category Chart** with interactive drilldown
- **Region filters** — Global, NA, EMEA, MENA, APAC, LATAM
- **Category filters** — Ransomware, Breach, DDoS, APT, and more
- **Article detail view** with IOC extraction
- **Light/dark theme** toggle

### Integration
- **RSS feed output** — subscribe from any feed reader or SIEM
- **JSON API** — programmatic access to all articles and stats
- **CORS enabled** — embed in other dashboards

---

## 🚀 Quick Start

### Docker Compose (recommended)

```bash
git clone https://github.com/your-org/threatwatch.git
cd threatwatch

# Create .env file (optional — works without it)
cp .env.example .env

# Start everything
docker compose up -d
```

The pipeline runs immediately on startup, then every 30 minutes. The dashboard is available at **http://localhost:8098**.

### Manual Setup

```bash
# Clone
git clone https://github.com/your-org/threatwatch.git
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

Set up a cron job for automatic refresh:

```cron
*/30 * * * * cd /path/to/threatwatch && /path/to/venv/bin/python threatdigest_main.py >> data/logs/cron.log 2>&1
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8098` | Dashboard server port |
| `SITE_DOMAIN` | `threatdigest.cyberonehq.com` | Domain for RSS feed links |
| `FEED_CUTOFF_DAYS` | `7` | Rolling window for articles |
| `DAILY_BUDGET_USD` | `2.00` | Daily budget cap for optional AI classification |
| `ANTHROPIC_API_KEY` | _(empty)_ | Optional — enables AI-enhanced classification |

### Feed Configuration

Feeds are defined in YAML files under `config/`:

| File | Description |
|---|---|
| `feeds_native.yaml` | Security blogs, vendor advisories, CERTs |
| `feeds_google.yaml` | Google News search queries |
| `feeds_bing.yaml` | Bing News search queries |

Add or remove feeds by editing these files. No restart required — changes take effect on the next pipeline run.

### Optional: AI-Enhanced Classification

ThreatWatch works fully without any API keys. Optionally, set `ANTHROPIC_API_KEY` to enable Claude-powered classification for improved accuracy. The system enforces a daily budget cap and caches results to minimize cost.

---

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  142 RSS     │────▶│  Fetch       │────▶│  Deduplicate │
│  Feeds       │     │  (8 threads) │     │  (shingle)   │
└─────────────┘     └──────────────┘     └──────┬───────┘
                                                │
                    ┌──────────────┐     ┌──────▼───────┐
                    │  Classify    │◀────│  Scrape      │
                    │  (keyword)   │     │  (full text)  │
                    └──────┬───────┘     └──────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  JSON    │ │  RSS     │ │  Dashboard│
        │  Output  │ │  Feed    │ │  (SSR)    │
        └──────────┘ └──────────┘ └──────────┘
```

**Pipeline** (`threatdigest_main.py`): Feeds → Fetch → Deduplicate → Scrape → Classify → Output

**Server** (`serve_threatwatch.py`): Python HTTP server with SSR, ETag caching, gzip compression, and CORS

**Frontend** (`threatwatch.html`): Single HTML file — no build step, no framework, no dependencies

**Storage**: File-based JSON — no database, no Redis, no message queue

### Project Structure

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
  ├── ai_engine.py       # Optional AI classification
  ├── briefing_generator.py  # Narrative summary builder
  ├── output_writer.py   # JSON/RSS output
  ├── config.py          # Global configuration
  └── ...
config/
  ├── feeds_native.yaml  # Security blogs & CERTs
  ├── feeds_google.yaml  # Google News feeds
  └── feeds_bing.yaml    # Bing News feeds
app/
  └── dashboard.py       # Dashboard data builder
scripts/
  ├── validate_feeds.py  # Feed health checker
  ├── cleanup.py         # Data cleanup utility
  └── weekly_digest.py   # Weekly summary generator
data/
  ├── output/            # JSON + RSS output files
  ├── state/             # Pipeline state & AI cache
  └── logs/              # Run logs & summaries
tests/                   # Test suite
docker-compose.yml       # Two-service deployment
Dockerfile               # Python 3.11-slim based
```

---

## 🔌 API Endpoints

The server exposes the following endpoints on port **8098**:

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard (server-side rendered HTML) |
| `GET` | `/api/articles` | All articles as JSON |
| `GET` | `/api/articles?offset=0&limit=20` | Paginated articles |
| `GET` | `/api/briefing` | Threat intelligence briefing |
| `GET` | `/api/stats` | Pipeline run statistics |
| `GET` | `/api/rss` | RSS feed (XML) |

All JSON endpoints support **CORS**, **ETag** conditional requests, and **gzip** compression.

---

## 🧪 Running Tests

```bash
# Install dev dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=modules --cov-report=term-missing
```

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create a branch** — `git checkout -b feat/your-feature`
3. **Write tests** — maintain 80%+ coverage
4. **Make your changes** — follow existing code style
5. **Run the test suite** — `pytest tests/ -v`
6. **Commit** — use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `refactor:`, etc.)
7. **Open a Pull Request** with a clear description

### Areas for Contribution

- Additional RSS feed sources
- New threat actor/malware family patterns
- Dashboard visualizations
- STIX/TAXII export support
- Webhook/notification integrations
- Performance improvements

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**ThreatWatch** — Threat intelligence that costs nothing and trusts no one.

</div>
