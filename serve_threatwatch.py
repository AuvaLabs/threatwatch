#!/usr/bin/env python3
"""Lightweight threaded HTTP server for ThreatWatch dashboard with server-side rendering."""

import collections
import gzip
import hashlib
import html
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from email.utils import formatdate
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent
PORT = int(os.environ.get("PORT", 8098))
CACHE_TTL = 30  # seconds
SSR_PLACEHOLDER = "<!-- __SSR_DATA__ -->"

_cache = {}
_ssr_lock = threading.Lock()

# ── Rate limiting ─────────────────────────────────────────────────────────────
_RATE_WINDOW  = 60   # seconds
_RATE_LIMIT   = 120  # requests per window per IP
_rate_buckets: dict = {}
_rate_lock    = threading.Lock()

def _is_rate_limited(ip: str) -> bool:
    """Sliding-window rate limiter. Returns True if the IP has exceeded the limit."""
    now = time.monotonic()
    with _rate_lock:
        dq = _rate_buckets.setdefault(ip, collections.deque())
        while dq and dq[0] < now - _RATE_WINDOW:
            dq.popleft()
        if len(dq) >= _RATE_LIMIT:
            return True
        dq.append(now)
        return False

# ── Security headers ──────────────────────────────────────────────────────────
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none';"
)
_SECURITY_HEADERS = {
    "Content-Security-Policy":   _CSP,
    "X-Frame-Options":           "DENY",
    "X-Content-Type-Options":    "nosniff",
    "Referrer-Policy":           "no-referrer",
    "Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
}


def read_cached(file_path):
    """Read file with in-memory cache (TTL-based)."""
    now = time.time()
    key = str(file_path)
    entry = _cache.get(key)
    if entry and (now - entry[0]) < CACHE_TTL:
        return entry[1]
    try:
        data = file_path.read_bytes()
        _cache[key] = (now, data)
        return data
    except FileNotFoundError:
        _cache.pop(key, None)
        raise


def load_articles():
    """Load articles JSON, cached."""
    articles_path = BASE_DIR / "data" / "output" / "daily_latest.json"
    try:
        raw = read_cached(articles_path)
        return json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def load_stats():
    """Load pipeline stats, cached."""
    stats_path = BASE_DIR / "data" / "output" / "stats.json"
    try:
        raw = read_cached(stats_path)
        return json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def load_briefing():
    """Load AI briefing, cached."""
    briefing_path = BASE_DIR / "data" / "output" / "briefing.json"
    try:
        raw = read_cached(briefing_path)
        return json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


_SERVER_START = time.time()


def build_health() -> bytes:
    """Build /api/health payload — not cached (always fresh)."""
    stats = load_stats()
    latest_run = stats.get("latest", {})

    # Feed health summary from state file
    feed_summary: dict[str, int] = {}
    feed_health_path = BASE_DIR / "data" / "state" / "feed_health.json"
    try:
        fh_raw = feed_health_path.read_bytes()
        fh_data = json.loads(fh_raw)
        for entry in fh_data.values():
            s = entry.get("status", "ok")
            feed_summary[s] = feed_summary.get(s, 0) + 1
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    payload = {
        "status": "ok",
        "uptime_s": int(time.time() - _SERVER_START),
        "last_run_at": latest_run.get("completed_at"),
        "articles_total": latest_run.get("articles_fetched", 0),
        "articles_cyber": latest_run.get("cyber_articles", 0),
        "api_cost_today_usd": latest_run.get("api_cost_today", 0),
        "feed_health": feed_summary,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build_ssr_data():
    """Build the server-side rendered data payload to embed in HTML.

    Uses a lock to prevent cache stampede: only one thread recomputes while
    others return stale data.
    """
    now = time.time()
    key = "__ssr_data__"
    entry = _cache.get(key)
    if entry and (now - entry[0]) < CACHE_TTL:
        return entry[1]

    # Try to acquire the lock; if another thread is already rebuilding,
    # return stale data (if available) instead of blocking.
    acquired = _ssr_lock.acquire(blocking=False)
    if not acquired:
        if entry:
            return entry[1]
        # No stale data and another thread is rebuilding — block until ready.
        with _ssr_lock:
            return _cache.get(key, (0, "{}"))[1]

    try:
        articles = load_articles()
        stats = load_stats()
        briefing = load_briefing()

        ssr_payload = {
            "articles": articles,
            "stats": stats,
            "briefing": briefing,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Serialize and cache
        ssr_json = json.dumps(ssr_payload, ensure_ascii=False, separators=(",", ":"))
        _cache[key] = (now, ssr_json)
        return ssr_json
    finally:
        _ssr_lock.release()


def render_page():
    """Read HTML template and inject SSR data."""
    now = time.time()
    key = "__rendered_page__"
    entry = _cache.get(key)
    if entry and (now - entry[0]) < CACHE_TTL:
        return entry[1]

    template_path = BASE_DIR / "threatwatch.html"
    template = read_cached(template_path).decode("utf-8")

    ssr_json = build_ssr_data()
    # Escape '</' sequences to prevent script injection / tag breakout (XSS).
    safe_json = ssr_json.replace("</", "<\\/")
    # Inject data as a script tag replacing the placeholder
    ssr_script = f'<script id="ssr-data" type="application/json">{safe_json}</script>'
    rendered = template.replace(SSR_PLACEHOLDER, ssr_script)

    body = rendered.encode("utf-8")
    _cache[key] = (now, body)
    return body


STATIC_ROUTES = {
    "/api/briefing": {
        "file": BASE_DIR / "data" / "output" / "briefing.json",
        "content_type": "application/json; charset=utf-8",
    },
    "/api/stats": {
        "file": BASE_DIR / "data" / "output" / "stats.json",
        "content_type": "application/json; charset=utf-8",
    },
    "/api/rss": {
        "file": BASE_DIR / "data" / "output" / "rss_cyberattacks.xml",
        "content_type": "application/xml; charset=utf-8",
    },
    "/favicon.svg": {
        "file": BASE_DIR / "favicon.svg",
        "content_type": "image/svg+xml",
    },
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("threatwatch")


class ThreatWatchHandler(BaseHTTPRequestHandler):
    """Request handler with SSR, CORS, and file-based routing."""

    server_version = "ThreatWatch/2.0"

    def log_message(self, fmt, *args):
        logger.info("%s %s", self.address_string(), fmt % args)

    def _is_api_path(self) -> bool:
        return urlparse(self.path).path.startswith("/api/")

    def _send_security_headers(self):
        for name, value in _SECURITY_HEADERS.items():
            self.send_header(name, value)

    def _send_cors_headers(self):
        """CORS only on /api/* routes — not on the HTML page."""
        if self._is_api_path():
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_error_json(self, status, message):
        payload = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self._send_security_headers()
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _send_body(self, content_type, body, head_only=False):
        """Send response with ETag, Last-Modified, and optional gzip compression."""
        # Compute ETag from raw body before any compression.
        etag = '"' + hashlib.md5(body).hexdigest() + '"'

        # Check If-None-Match for conditional GET (304 Not Modified).
        if_none_match = self.headers.get("If-None-Match", "")
        if if_none_match == etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", etag)
            self._send_security_headers()
            self._send_cors_headers()
            self.end_headers()
            return

        accept_enc = self.headers.get("Accept-Encoding", "")
        if "gzip" in accept_enc and len(body) > 1024:
            body = gzip.compress(body, compresslevel=6)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Encoding", "gzip")
        else:
            self.send_response(HTTPStatus.OK)

        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=30")
        self.send_header("ETag", etag)
        self.send_header("Last-Modified", formatdate(timeval=time.time(), usegmt=True))
        self._send_security_headers()
        self._send_cors_headers()
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_security_headers()
        self._send_cors_headers()
        self.end_headers()

    def do_HEAD(self):
        self._handle_request(head_only=True)

    def do_GET(self):
        self._handle_request(head_only=False)

    def _handle_request(self, head_only=False):
        client_ip = self.client_address[0]
        if _is_rate_limited(client_ip):
            self._send_error_json(HTTPStatus.TOO_MANY_REQUESTS,
                                  "Rate limit exceeded — max 120 requests per minute")
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)

        # Route: / — server-side rendered HTML
        if path == "/":
            try:
                body = render_page()
            except FileNotFoundError:
                self._send_error_json(HTTPStatus.NOT_FOUND, "Template not available")
                return
            except OSError as exc:
                logger.error("Error rendering page: %s", exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Render error")
                return
            self._send_body("text/html; charset=utf-8", body, head_only)
            return

        # Route: /api/health — liveness + stats
        if path == "/api/health":
            body = build_health()
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Route: /api/articles — with pagination support
        if path == "/api/articles":
            try:
                articles = load_articles()
            except OSError:
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Error loading articles")
                return

            # Pagination params with bounds checking
            try:
                offset = int(params.get("offset", [0])[0])
            except (ValueError, TypeError):
                self._send_error_json(HTTPStatus.BAD_REQUEST, "offset must be an integer")
                return
            try:
                limit = int(params.get("limit", [0])[0])  # 0 = return all
            except (ValueError, TypeError):
                self._send_error_json(HTTPStatus.BAD_REQUEST, "limit must be an integer")
                return

            total = len(articles)
            offset = max(0, min(offset, total))
            limit = max(0, min(limit, 100))

            if limit > 0:
                page = articles[offset:offset + limit]
                result = {
                    "articles": page,
                    "total": len(articles),
                    "offset": offset,
                    "limit": limit,
                    "has_more": offset + limit < len(articles),
                }
            else:
                result = articles  # Backwards compatible: return full array

            body = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Static routes
        route = STATIC_ROUTES.get(path)
        if route is None:
            self._send_error_json(HTTPStatus.NOT_FOUND, f"Not found: {path}")
            return

        try:
            body = read_cached(route["file"])
        except FileNotFoundError:
            self._send_error_json(HTTPStatus.NOT_FOUND, f"Data file not available: {route['file'].name}")
            return
        except OSError as exc:
            logger.error("Error reading %s: %s", route["file"], exc)
            self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error")
            return

        self._send_body(route["content_type"], body, head_only)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTPServer that handles each request in a new thread."""

    daemon_threads = True
    allow_reuse_address = True


def main():
    server = ThreadedHTTPServer(("0.0.0.0", PORT), ThreatWatchHandler)
    logger.info("ThreatWatch v2.0 server starting on http://0.0.0.0:%d", PORT)
    logger.info("Base directory: %s", BASE_DIR)
    logger.info("SSR enabled — articles embedded in HTML on each request")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
