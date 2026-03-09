# Contributing to ThreatWatch

Thanks for your interest in contributing! Here's how to get started.

## Quick Start

```bash
git clone https://github.com/YOUR_ORG/threatwatch.git
cd threatwatch
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 threatdigest_main.py   # Run pipeline once
python3 serve_threatwatch.py   # Start dashboard
```

## Ways to Contribute

### Add Feed Sources
Edit `config/feeds_native.yaml` to add RSS feeds from security blogs, CERTs, or vendors.

```yaml
- url: https://example.com/feed.xml
  region: US
```

### Add Threat Actor Patterns
Edit `ACTOR_PATTERNS` in `threatwatch.html` to detect new threat actors.

### Add Classification Rules
Edit `modules/keyword_classifier.py` to add regex rules for new threat categories.

### Add Country Detection
Edit `COUNTRY_KEYWORDS` in `threatwatch.html` for new country/city keyword mappings.

### Add Sector Patterns
Edit `SECTOR_PATTERNS` in `threatwatch.html` for new industry sector detection.

## Pull Request Process

1. Fork the repo and create a feature branch
2. Make your changes
3. Run tests: `pytest tests/`
4. Submit a PR with a clear description

## Code Style

- Python: PEP 8, type hints welcome
- JavaScript: No frameworks, keep it in the single HTML file
- Keep modules small and focused (<400 lines)
- No external services required (no database, no Redis)

## Reporting Issues

Open a GitHub issue with:
- What you expected
- What happened
- Steps to reproduce
- Your environment (OS, Python version)
