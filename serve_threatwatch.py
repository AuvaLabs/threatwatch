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
WATCHLIST_WRITE_ENABLED = os.environ.get("WATCHLIST_WRITE_ENABLED", "").lower() in ("1", "true", "yes")
WATCHLIST_TOKEN = os.environ.get("WATCHLIST_TOKEN", "")

_cache = {}
_ssr_lock = threading.Lock()

# ── Rate limiting ─────────────────────────────────────────────────────────────
_RATE_WINDOW  = 60   # seconds
_RATE_LIMIT   = 120  # requests per window per IP
_RATE_MAX_IPS = 10_000  # max tracked IPs to prevent memory leak
_rate_buckets: dict = {}
_rate_lock    = threading.Lock()

def _is_rate_limited(ip: str) -> bool:
    """Sliding-window rate limiter. Returns True if the IP has exceeded the limit."""
    now = time.monotonic()
    with _rate_lock:
        # Evict stale IPs periodically to prevent unbounded memory growth
        if len(_rate_buckets) > _RATE_MAX_IPS:
            stale = [k for k, dq in _rate_buckets.items()
                     if not dq or dq[-1] < now - _RATE_WINDOW]
            for k in stale:
                del _rate_buckets[k]

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
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self'; "
    "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "frame-ancestors 'none';"
)
_SECURITY_HEADERS = {
    "Content-Security-Policy":   _CSP,
    "X-Frame-Options":           "DENY",
    "X-Content-Type-Options":    "nosniff",
    "Referrer-Policy":           "no-referrer",
    "Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
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


def load_top_stories():
    """Load AI-curated top stories."""
    path = BASE_DIR / "data" / "output" / "top_stories.json"
    try:
        raw = read_cached(path)
        return json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def load_clusters():
    """Load incident clusters."""
    path = BASE_DIR / "data" / "output" / "clusters.json"
    try:
        raw = read_cached(path)
        return json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def load_actor_profiles():
    """Load threat actor profiles."""
    path = BASE_DIR / "data" / "output" / "actor_profiles.json"
    try:
        raw = read_cached(path)
        return json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


_SERVER_START = time.time()


# ── Watchlist helpers ─────────────────────────────────────────────────────────

def load_watchlist_data() -> dict:
    """Load watchlist.json from STATE_DIR. Returns empty structure if missing."""
    watchlist_path = BASE_DIR / "data" / "state" / "watchlist.json"
    try:
        with open(watchlist_path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"brands": [], "assets": [], "updated_at": None}


_watchlist_lock = threading.Lock()


def save_watchlist_data(brands: list, assets: list) -> None:
    """Persist watchlist to STATE_DIR/watchlist.json (thread-safe)."""
    watchlist_path = BASE_DIR / "data" / "state" / "watchlist.json"
    watchlist_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "brands": [str(b).strip() for b in brands if str(b).strip()],
        "assets": [str(a).strip() for a in assets if str(a).strip()],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    with _watchlist_lock:
        tmp = watchlist_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        tmp.replace(watchlist_path)


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
        top_stories = load_top_stories()
        clusters = load_clusters()
        actor_profiles = load_actor_profiles()

        # Strip full_content from SSR payload to reduce page size
        # (full_content is only needed for article detail view via API)
        ssr_articles = [
            {k: v for k, v in a.items() if k != "full_content"}
            for a in articles
        ]

        ssr_payload = {
            "articles": ssr_articles,
            "stats": stats,
            "briefing": briefing,
            "top_stories": top_stories,
            "clusters": clusters,
            "actor_profiles": actor_profiles,
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


def load_ioc_items() -> list:
    """Load IOC (ThreatFox) items from the full article list."""
    articles = load_articles()
    return [a for a in articles if a.get("isDarkweb") and a.get("darkwebSource") == "threatfox"]


STATIC_ROUTES = {
    "/api/briefing": {
        "file": BASE_DIR / "data" / "output" / "briefing.json",
        "content_type": "application/json; charset=utf-8",
    },
    "/api/top-stories": {
        "file": BASE_DIR / "data" / "output" / "top_stories.json",
        "content_type": "application/json; charset=utf-8",
    },
    "/api/clusters": {
        "file": BASE_DIR / "data" / "output" / "clusters.json",
        "content_type": "application/json; charset=utf-8",
    },
    "/api/actor-profiles": {
        "file": BASE_DIR / "data" / "output" / "actor_profiles.json",
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

    # Endpoints that expose internal metrics — restrict CORS to same-origin only
    _RESTRICTED_CORS_PATHS = frozenset({"/api/health", "/api/watchlist"})

    def _send_cors_headers(self):
        """CORS only on /api/* routes — restricted on sensitive endpoints."""
        if not self._is_api_path():
            return
        path = urlparse(self.path).path.rstrip("/")
        if path in self._RESTRICTED_CORS_PATHS:
            origin = self.headers.get("Origin", "")
            allowed = os.environ.get("CORS_ORIGIN", "")
            if allowed and origin == allowed:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            # If no CORS_ORIGIN configured or origin doesn't match, omit the header
            # (browser will block the cross-origin request)
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

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

    def do_POST(self):
        client_ip = self.client_address[0]
        if _is_rate_limited(client_ip):
            self._send_error_json(HTTPStatus.TOO_MANY_REQUESTS, "Rate limit exceeded")
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/api/watchlist":
            if not WATCHLIST_WRITE_ENABLED:
                self._send_error_json(HTTPStatus.FORBIDDEN,
                                      "Watchlist write not enabled on this instance. "
                                      "Set WATCHLIST_WRITE_ENABLED=true to allow.")
                return
            # Token auth when WATCHLIST_TOKEN is configured
            if WATCHLIST_TOKEN:
                auth = self.headers.get("Authorization", "")
                if auth != f"Bearer {WATCHLIST_TOKEN}":
                    self._send_error_json(HTTPStatus.UNAUTHORIZED, "Invalid or missing authorization token")
                    return
            try:
                length = int(self.headers.get("Content-Length", 0))
                if length > 65536:  # 64 KB max payload
                    self._send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Payload too large")
                    return
                raw = self.rfile.read(length)
                data = json.loads(raw)
                brands = [str(b).strip()[:200] for b in data.get("brands", [])[:50] if str(b).strip()]
                assets = [str(a).strip()[:200] for a in data.get("assets", [])[:50] if str(a).strip()]
                save_watchlist_data(brands, assets)
                body = json.dumps({"ok": True, "brands": len(brands), "assets": len(assets)}).encode()
            except (json.JSONDecodeError, ValueError):
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid JSON payload")
                return
            except OSError as exc:
                logger.error("Watchlist write failed: %s", exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Write failed")
                return
            self._send_body("application/json; charset=utf-8", body, False)
            return

        self._send_error_json(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed")

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

        # Route: /api/trends — threat trend data and spike detection
        if path == "/api/trends":
            try:
                from modules.trend_detector import get_trends_report
                report = get_trends_report()
                body = json.dumps(report, ensure_ascii=False).encode("utf-8")
            except Exception as exc:
                logger.error("Trends report error: %s", exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Trends report failed")
                return
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Route: /api/quality — data quality metrics and feed health
        if path == "/api/quality":
            try:
                from modules.feed_health import get_health_json
                articles = load_articles()
                from collections import Counter
                cat_counts = Counter(a.get("category", "Unknown") for a in articles)
                conf_counts = Counter(a.get("confidence", 0) for a in articles)
                unclassified = sum(1 for a in articles
                                   if a.get("category") == "General Cyber Threat"
                                   and a.get("confidence", 0) == 60)
                no_summary = sum(1 for a in articles if not a.get("summary"))
                with_epss = sum(1 for a in articles if a.get("epss_scores"))
                with_attack = sum(1 for a in articles if a.get("attack_techniques"))
                with_cvss = sum(1 for a in articles if a.get("cvss_score"))

                quality = {
                    "total_articles": len(articles),
                    "unclassified_count": unclassified,
                    "unclassified_pct": round(unclassified / max(len(articles), 1) * 100, 1),
                    "no_summary_count": no_summary,
                    "enrichment": {
                        "epss_enriched": with_epss,
                        "attack_tagged": with_attack,
                        "cvss_scored": with_cvss,
                    },
                    "category_distribution": dict(cat_counts.most_common(15)),
                    "feed_health": get_health_json(),
                }
                body = json.dumps(quality, ensure_ascii=False).encode("utf-8")
            except Exception as exc:
                logger.error("Quality report error: %s", exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Quality report failed")
                return
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Route: /api/health — liveness + stats
        if path == "/api/health":
            body = build_health()
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Route: /api/stix — STIX 2.1 bundle export
        if path == "/api/stix":
            try:
                from modules.stix_output import build_stix_bytes
                articles = [a for a in load_articles()
                            if not (a.get("isDarkweb") and a.get("darkwebSource") == "threatfox")]
                ioc_items = load_ioc_items()
                body = build_stix_bytes(articles, ioc_items)
            except Exception as exc:
                logger.error("STIX generation error: %s", exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "STIX generation failed")
                return
            self._send_body("application/stix+json; charset=utf-8", body, head_only)
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
            else:
                page = articles[offset:]

            result = {
                "articles": page,
                "total": total,
                "offset": offset,
                "limit": limit,
                "has_more": (offset + len(page)) < total,
            }

            body = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Route: /api/watchlist — GET returns current watchlist + vendor suggest-list
        if path == "/api/watchlist":
            try:
                from modules.watchlist_monitor import VENDOR_SUGGEST_LIST
                watchlist = load_watchlist_data()
                payload = {
                    "brands": watchlist.get("brands", []),
                    "assets": watchlist.get("assets", []),
                    "updated_at": watchlist.get("updated_at"),
                    "write_enabled": WATCHLIST_WRITE_ENABLED,
                    "suggest_list": VENDOR_SUGGEST_LIST,
                }
                body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            except Exception as exc:
                logger.error("Watchlist GET error: %s", exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Watchlist unavailable")
                return
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Static routes
        route = STATIC_ROUTES.get(path)
        if route is None:
            self._send_error_json(HTTPStatus.NOT_FOUND, "Not found")
            return

        try:
            body = read_cached(route["file"])
        except FileNotFoundError:
            self._send_error_json(HTTPStatus.NOT_FOUND, "Data file not available")
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
