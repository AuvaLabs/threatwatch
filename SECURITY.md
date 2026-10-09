# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `main` | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in ThreatWatch, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email **security@auvalabs.com** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. You will receive an acknowledgement within 48 hours
4. We will work with you to understand and fix the issue before any public disclosure

## Security Controls

ThreatWatch implements the following protections:

- **Content Security Policy (CSP)** with frame-ancestors, script-src, font-src restrictions
- **HSTS** (Strict-Transport-Security) with preload
- **Rate limiting** — 120 requests/minute per IP (sliding window) with automatic stale IP eviction
- **SSRF protection** — URL validation before fetching external resources
- **XSS prevention** — HTML escaping on all user-controlled output; SSR JSON injection uses `</` escaping; STIX pattern injection sanitization
- **Non-root Docker** — container runs as UID 1001 unprivileged user
- **Security headers** — X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy no-referrer
- **Dependency auditing**: `pip-audit` and `npm audit` run in CI on every push
- **Code scanning**: extended Python and JavaScript analysis runs on the default branch
- **Bearer token auth** — optional token protection for watchlist write endpoint
- **CORS restriction** — sensitive endpoints (`/api/health`, `/api/watchlist`) require `CORS_ORIGIN` match; public data endpoints allow wildcard
- **Atomic file writes** — watchlist persistence uses tmp+rename to prevent corruption under concurrent requests
- **Payload limits** — 64KB max POST body on watchlist endpoint; input truncation (200 chars/item, 50 items max)

## Scope

The following are in scope:

- `threatdigest_main.py` and `modules/` — pipeline code
- `serve_threatwatch.py` — HTTP server
- `frontend/src/` and the Vite build: analyst workspace frontend
- `scripts/` — deployment and utility scripts
- Docker configuration

The following are out of scope:

- Third-party RSS feed content
- Issues in upstream dependencies (report those to the respective projects)

## Best Practices for Self-Hosting

- Run behind a reverse proxy (nginx, Caddy) with TLS
- Do not expose the Python HTTP server directly to the internet
- Keep your `.env` file out of version control (it is gitignored by default)
- Set `WATCHLIST_TOKEN` when enabling server-side watchlist writes
- Set `CORS_ORIGIN` to your production domain to restrict cross-origin access to sensitive API endpoints
- Private LLM endpoints are trusted only when their exact host and port are configured in a supported provider base URL variable
- Rotate LLM API keys regularly if using AI briefing
- Review feed configurations before deploying in sensitive environments
