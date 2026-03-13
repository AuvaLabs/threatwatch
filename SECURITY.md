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

## Scope

The following are in scope:

- `threatdigest_main.py` and `modules/` — pipeline code
- `serve_threatwatch.py` — HTTP server
- `threatwatch.html` — dashboard frontend
- `scripts/` — deployment and utility scripts
- Docker configuration

The following are out of scope:

- Third-party RSS feed content
- Issues in upstream dependencies (report those to the respective projects)

## Best Practices for Self-Hosting

- Run behind a reverse proxy (nginx, Caddy) with TLS
- Do not expose the Python HTTP server directly to the internet
- Keep your `.env` file out of version control (it is gitignored by default)
- Rotate LLM API keys regularly if using AI briefing
- Review feed configurations before deploying in sensitive environments
