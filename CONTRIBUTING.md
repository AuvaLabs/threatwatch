# Contributing to ThreatWatch

Thank you for contributing to ThreatWatch. Contributions are accepted under the project's [non-commercial license](LICENSE).

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Setup

```bash
git clone https://github.com/AuvaLabs/threatwatch.git
cd threatwatch
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cd frontend
npm ci
npm test
npm run build
cd ..

python3 threatdigest_main.py
python3 serve_threatwatch.py
```

## Ways to contribute

### Add feed sources
Edit `config/feeds_native.yaml` to add RSS feeds from security blogs, CERTs, or vendors.

```yaml
- url: https://example.com/feed.xml
  region: US
```

### Add threat actor patterns
Edit `ACTOR_PATTERNS` in `modules/entities.py` and add focused tests in `tests/test_entities.py`.

### Add classification rules
Edit `modules/keyword_classifier.py` to add regex rules for new threat categories.

### Improve region detection
Update `modules/region_inferrer.py` and `modules/regions.py`, then add regression cases in `tests/test_region_fixes.py`.

### Add sector patterns
Update `_SECTOR_PATTERNS` in `modules/victim_tagger.py` and add cases in `tests/test_victim_tagger.py`.

### Improve the analyst workspace
The Preact and TypeScript application lives under `frontend/src/`. Keep API access in `frontend/src/services/`, reusable presentation in `frontend/src/components/`, and workspace pages in `frontend/src/views/`.

## Pull request process

1. Fork the repo and create a feature branch
2. Make your changes
3. Run the complete local harness shown below
4. Submit a pull request with a clear description and testing evidence

```bash
ruff check .
pytest tests/ --cov=modules --cov=serve_threatwatch --cov-fail-under=80

cd frontend
npm test
npm run build
npm audit --audit-level=high
cd ..

docker build -t threatwatch:local .
```

## Code style

- Python: PEP 8, type hints welcome
- Frontend: typed Preact components, explicit loading and failure states, and accessible interaction patterns
- Keep modules small and focused (under 400 lines)
- SQLite and local JSON artifacts remain the default persistence layer
- Optional external providers must degrade safely when credentials or services are unavailable

## Reporting issues

Open a GitHub issue with:
- What you expected
- What happened
- Steps to reproduce
- Your environment (OS, Python version)
