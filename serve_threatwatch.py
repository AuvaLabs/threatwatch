#!/usr/bin/env python3
"""Lightweight threaded HTTP server for ThreatWatch dashboard with server-side rendering."""

import collections
import gzip
import hashlib
import hmac
import html
import json
import logging
import math
import mimetypes
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, unquote, urlparse

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
PORT = int(os.environ.get("PORT", 8098))
CACHE_TTL = 30  # seconds
WATCHLIST_WRITE_ENABLED = os.environ.get("WATCHLIST_WRITE_ENABLED", "").lower() in ("1", "true", "yes")
WATCHLIST_TOKEN = os.environ.get("WATCHLIST_TOKEN", "")
# SQLite read path toggle. When set, load_articles prefers the shadow store
# over JSON. Off by default so the cut-over is explicit and reversible: set
# READ_FROM_SQLITE=1 in docker-compose to enable, unset to revert to JSON.
_READ_FROM_SQLITE = os.environ.get("READ_FROM_SQLITE", "").lower() in ("1", "true", "yes")

_cache: dict = {}
_cache_lock = threading.Lock()  # guards all _cache writes; reads use GIL
# Single-entry gzip memo: (etag, compressed_bytes). The rendered page is
# identical for every request inside the 30s cache window, but each request
# used to re-run gzip on ~400KB. One slot is enough — the page dominates
# traffic and API bodies are cheap to compress.
_gzip_memo: tuple = ("", b"")
_gzip_memo_lock = threading.Lock()

# Peers from which we trust forwarded-IP headers. Behind nginx every request
# appears to come from 127.0.0.1, so without this every public user is bucketed
# into the same rate-limit window. We only honour the header when the TCP peer
# is actually a trusted proxy — a direct-to-port attacker cannot forge their
# way into a separate bucket.
_TRUSTED_PROXIES = frozenset(
    ip.strip() for ip in os.environ.get("TRUSTED_PROXIES", "127.0.0.1,::1").split(",")
    if ip.strip()
)


def _get_client_ip(handler) -> str:
    """Return the effective client IP for rate-limiting / logging.

    Prefers `X-Real-IP` (set by nginx `proxy_set_header X-Real-IP $remote_addr`)
    when the TCP peer is a configured trusted proxy. Falls back to
    `client_address[0]` otherwise, which fails closed if the header is forged
    from outside the proxy layer.
    """
    peer = handler.client_address[0]
    if peer in _TRUSTED_PROXIES:
        forwarded = handler.headers.get("X-Real-IP", "").strip()
        if forwarded:
            return forwarded
    return peer

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
# The replacement frontend ships external scripts and styles only. Keeping
# inline execution disabled lets feed content remain untrusted by default.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
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
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
}


def read_cached(file_path):
    """Read file with an mtime-validated in-memory cache.

    A cache hit additionally checks the file's mtime: the pipeline rewrites
    these files atomically (tmp+rename bumps mtime), so a changed mtime means
    the cached bytes are stale even inside the TTL window. A pure-TTL cache
    served up-to-30s-old data right after a pipeline write and let the
    SQLite/JSON parity check compare a fresh DB count against a stale JSON
    count. The stat() costs microseconds; the TTL still bounds entry age.

    Reads of `_cache` rely on the GIL for atomicity; writes take `_cache_lock`
    so a concurrent read never sees a half-populated tuple, and the
    check-then-set is race-free against parallel evictions.
    """
    now = time.time()
    key = str(file_path)
    entry = _cache.get(key)
    if entry and len(entry) == 3 and (now - entry[0]) < CACHE_TTL:
        try:
            if file_path.stat().st_mtime == entry[2]:
                return entry[1]
        except FileNotFoundError:
            with _cache_lock:
                _cache.pop(key, None)
            raise
    try:
        mtime = file_path.stat().st_mtime
        data = file_path.read_bytes()
        with _cache_lock:
            _cache[key] = (now, data, mtime)
        return data
    except FileNotFoundError:
        with _cache_lock:
            _cache.pop(key, None)
        raise


def load_articles():
    """Return the full article corpus as a list of dicts.

    SQLite Phase 3: READ_FROM_SQLITE=1 is active in production. SQLite is the
    primary read source with a 7-day prune applied each pipeline run. JSON
    files are kept as backup and provide the parity-check reference count.
    Fallback to JSON triggers only if SQLite has >20% fewer rows than JSON.
    """
    if _READ_FROM_SQLITE:
        try:
            from modules.db import load_articles_from_db, count_articles
            db_count = count_articles()
            if db_count > 0:
                arts = load_articles_from_db()
                # Defensive parity check: if SQLite looks catastrophically
                # behind JSON (e.g. >20% fewer rows), fall back to JSON this
                # request so operators never see a half-empty dashboard
                # during a migration gap. Threshold keeps normal drift tolerant.
                json_count = _count_articles_json()
                if json_count > 0 and db_count < json_count * 0.8:
                    logger.warning(
                        "SQLite read disabled for this request: "
                        "db_count=%d json_count=%d", db_count, json_count,
                    )
                else:
                    return arts
        except Exception as exc:
            logger.warning("SQLite read failed, falling back to JSON: %s", exc)

    articles_path = BASE_DIR / "data" / "output" / "daily_latest.json"
    try:
        raw = read_cached(articles_path)
        return json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _count_articles_json() -> int:
    """Cheap row-count for the JSON primary, used as a parity reference."""
    try:
        raw = read_cached(BASE_DIR / "data" / "output" / "daily_latest.json")
        data = json.loads(raw)
        return len(data) if isinstance(data, list) else 0
    except (FileNotFoundError, json.JSONDecodeError):
        return 0


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


def load_trends():
    """Load trending-threats report (spikes + top keywords/categories).

    Same flat-file pattern as load_top_stories; trend_detector.py writes
    data/state/trends.json each pipeline run, but for the SSR payload we
    want the aggregated *report* shape (spikes + 7d/30d top lists), so
    we call get_trends_report() rather than reading the raw file.
    """
    try:
        from modules.trend_detector import get_trends_report
        return get_trends_report()
    except Exception:
        return None


def load_clusters():
    """Load incident clusters."""
    path = BASE_DIR / "data" / "output" / "clusters.json"
    try:
        raw = read_cached(path)
        return json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


# CVE IDs in URL paths — tight regex to avoid any injection surface in
# `_build_cve_view`, which accepts arbitrary path tail under /api/cve/.
import re as _re_cve
_CVE_PATH_RE = _re_cve.compile(r"CVE-\d{4}-\d{4,7}")
# Campaign IDs are UUID4s minted by campaign_tracker.
_CAMPAIGN_ID_RE = _re_cve.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def _db_stats_safe() -> dict:
    """Return SQLite shadow-store stats and the current read-source flag so
    operators can see at a glance whether the server is reading from SQLite
    or from JSON for a given request."""
    try:
        from modules.db import stats as db_stats
        s = db_stats()
        s["read_source"] = "sqlite" if _READ_FROM_SQLITE else "json"
        return s
    except Exception:
        return {
            "article_count": 0, "campaign_count": 0, "db_bytes": 0,
            "enabled": False, "read_source": "json",
        }


def _feedback_summary() -> dict:
    """Aggregate classifier feedback from data/state/feedback.jsonl.

    Returns total submissions and the top flagged correct_category values.
    Non-fatal: missing or malformed lines are skipped, never raise.
    """
    path = BASE_DIR / "data" / "state" / "feedback.jsonl"
    if not path.exists():
        return {"total": 0, "top_corrections": []}
    total = 0
    cat_counts: dict[str, int] = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                total += 1
                cc = rec.get("correct_category", "")
                if cc:
                    cat_counts[cc] = cat_counts.get(cc, 0) + 1
    except OSError:
        return {"total": 0, "top_corrections": []}
    top = sorted(cat_counts.items(), key=lambda x: -x[1])[:10]
    return {"total": total, "top_corrections": [{"category": c, "count": n} for c, n in top]}


def _enrich_campaign_with_articles(campaign: dict) -> dict:
    """Attach first_reported + per-article metadata to a campaign record.

    The persisted campaign only carries a list of article hashes (capped at
    500) to keep campaigns.json small. Analysts need to see *which* outlets
    covered the campaign and *when*. Here we cross-reference with the live
    daily_latest.json, sort by published ascending, and expose the earliest
    as `first_reported` plus the full matched list as `articles`.
    """
    from modules.date_utils import parse_datetime
    hashes = set(campaign.get("article_hashes") or [])
    matched = []
    if hashes:
        for a in load_articles():
            if a.get("hash") in hashes:
                matched.append({
                    "title": a.get("title"),
                    "translated_title": a.get("translated_title"),
                    "link": a.get("link"),
                    "source_name": a.get("source_name"),
                    "published": a.get("published"),
                    "category": a.get("category"),
                    "feed_region": a.get("feed_region"),
                })

    def _sort_key(a: dict):
        dt = parse_datetime(a.get("published"))
        return dt or datetime(9999, 12, 31, tzinfo=timezone.utc)

    matched.sort(key=_sort_key)
    first_reported = matched[0] if matched else None
    return {
        **campaign,
        "first_reported": first_reported,
        "articles": matched,
        "articles_in_window": len(matched),
    }


def _build_cve_view(cve_id: str) -> bytes:
    """Return all articles referencing `cve_id`, earliest first.

    The payload is self-contained so a future dedicated CVE page can render
    with a single fetch: timeline, per-article metadata, EPSS score from
    whichever enriched article carries it, and the full set of outlets
    covering the story.
    """
    from modules.date_utils import parse_datetime
    articles = load_articles()
    matching = []
    epss_score = None
    for a in articles:
        cves = a.get("cve_ids") or []
        if cve_id not in cves:
            continue
        matching.append(a)
        if epss_score is None:
            # `epss_scores` is a list of {cve_id, epss_score, ...} dicts per
            # the EPSS enricher output. Pull the score matching THIS CVE if
            # present; otherwise take the first numeric score we see.
            for entry in (a.get("epss_scores") or []):
                if not isinstance(entry, dict):
                    continue
                score = entry.get("epss_score")
                if isinstance(score, (int, float)):
                    if entry.get("cve_id", "").upper() == cve_id:
                        epss_score = float(score)
                        break
                    if epss_score is None:
                        epss_score = float(score)

    def _sort_key(a: dict):
        dt = parse_datetime(a.get("published")) or parse_datetime(a.get("timestamp"))
        return dt or datetime(1970, 1, 1, tzinfo=timezone.utc)

    matching.sort(key=_sort_key)
    first_reported = matching[0] if matching else None

    payload = {
        "cve_id": cve_id,
        "article_count": len(matching),
        "first_reported": (
            {
                "title": first_reported.get("title"),
                "source_name": first_reported.get("source_name"),
                "link": first_reported.get("link"),
                "published": first_reported.get("published"),
            } if first_reported else None
        ),
        "epss_score": epss_score,
        "articles": [
            {
                "title": a.get("title"),
                "translated_title": a.get("translated_title"),
                "link": a.get("link"),
                "source_name": a.get("source_name"),
                "published": a.get("published"),
                "timestamp": a.get("timestamp"),
                "category": a.get("category"),
                "confidence": a.get("confidence"),
                "summary": a.get("summary"),
                "feed_region": a.get("feed_region"),
            }
            for a in matching
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


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


_PIPELINE_INTERVAL_S = int(os.environ.get("PIPELINE_INTERVAL", "600"))
# A full pipeline run takes hours because of the LLM briefing / regional
# digest / summarisation phases, not the fetch loop. We therefore separate
# two liveness signals:
#   - HEARTBEAT_STALE_S: scheduler loop tick freshness (should be seconds).
#   - RUN_STALE_S: last_completed_run freshness (tolerates long LLM phases).
# If the heartbeat is fresh, the scheduler is alive even when the last
# finalised run is several hours old — that's the accurate picture.
_HEARTBEAT_STALE_S = max(_PIPELINE_INTERVAL_S * 3, 300)
_RUN_STALE_S = int(os.environ.get("RUN_STALE_S", "21600"))  # 6h default
_DEGRADED_FAILURE_RATE = 0.30
_BRIEFING_STALE_HOURS = float(os.environ.get("BRIEFING_STALE_HOURS", "3"))
_HEARTBEAT_PATH = "data/state/scheduler_heartbeat.txt"


def _compute_status(latest_run: dict, feed_summary: dict,
                    last_run_age: float | None, heartbeat_age: float | None,
                    briefing_stale: bool | None = None,
                    briefing_age_hours: float | None = None) -> tuple[str, list[str]]:
    """Decide ok / degraded / stale / unknown.

    Priority order:
    1. Heartbeat missing or older than HEARTBEAT_STALE_S => scheduler is dead.
    2. Last completed run older than RUN_STALE_S => pipeline may be stuck.
    3. Budget exceeded / analysis failures / dead feed count => degraded.
    4. Briefing stale => degraded; and if the pipeline is demonstrably live
       (heartbeat + last run fresh) while the briefing stays frozen, the AI
       generation layer itself is failing (e.g. provider 402/401 outage) even
       though the pipeline keeps completing runs — surface that distinctly so
       an uptime monitor watching /api/health catches it instead of the outage
       hiding behind a green status for days (the 2026-07 AI-provider outage).
    5. Otherwise ok.
    """
    reasons: list[str] = []
    if heartbeat_age is None:
        if last_run_age is None:
            return ("unknown", ["no_heartbeat_no_completed_run"])
    elif heartbeat_age > _HEARTBEAT_STALE_S:
        reasons.append(f"heartbeat_{int(heartbeat_age)}s_ago_threshold_{int(_HEARTBEAT_STALE_S)}s")
        return ("stale", reasons)
    if last_run_age is None:
        reasons.append("no_completed_run_recorded")
    elif last_run_age > _RUN_STALE_S:
        reasons.append(f"last_run_{int(last_run_age)}s_ago_threshold_{int(_RUN_STALE_S)}s")
    if latest_run.get("budget_exceeded"):
        reasons.append("llm_budget_exceeded_last_run")
    enriched = latest_run.get("articles_enriched") or 0
    failures = latest_run.get("analysis_failures") or 0
    if enriched and failures / max(enriched, 1) >= _DEGRADED_FAILURE_RATE:
        reasons.append(f"analysis_failure_rate_{failures}/{enriched}")
    dead_feeds = feed_summary.get("dead", 0) + feed_summary.get("failing", 0)
    if dead_feeds > 20:
        reasons.append(f"dead_feeds_{dead_feeds}")

    # Briefing freshness — Signal 1 (stale) and Signal 2 (AI generation frozen
    # while the pipeline is live). Guarded so a briefing_health import/read
    # failure (briefing_stale is None) never fabricates a health reason.
    if briefing_stale:
        if briefing_age_hours is not None and math.isfinite(briefing_age_hours):
            age_h = int(briefing_age_hours)
        else:
            age_h = "?"  # inf => briefing.json missing/unreadable
        reasons.append(f"briefing_stale_{age_h}h")
        pipeline_live = (
            heartbeat_age is not None and heartbeat_age <= _HEARTBEAT_STALE_S
            and last_run_age is not None and last_run_age <= _RUN_STALE_S
        )
        # Severe = beyond 2x the staleness threshold, i.e. multiple pipeline
        # ticks have completed without producing a fresh brief. A live pipeline
        # that cannot refresh the brief means AI generation is failing, not that
        # the brief is merely a tick behind.
        severe = (
            briefing_age_hours is not None
            and briefing_age_hours >= 2 * _BRIEFING_STALE_HOURS
        )
        if pipeline_live and severe:
            reasons.append("ai_generation_failing")
    return ("degraded" if reasons else "ok", reasons)


def build_health() -> bytes:
    """Build /api/health payload — not cached (always fresh).

    `status` reflects real state:
      ok      — last run completed within 2.5x pipeline interval, no LLM outage
      degraded— recent run completed but had LLM budget/failure or many dead feeds
      stale   — no recent run (pipeline hung or scheduler dead)
      unknown — no stats file yet
    """
    stats = load_stats()
    latest_run = stats.get("latest", {})

    feed_summary: dict[str, int] = {}
    feed_health_path = BASE_DIR / "data" / "state" / "feed_health.json"
    # Only count feeds that were actually checked in the last 24h. Entries for
    # feeds disabled in config linger in feed_health.json with their last error
    # status forever and otherwise inflate the error count on /api/health.
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    try:
        fh_raw = feed_health_path.read_bytes()
        fh_data = json.loads(fh_raw)
        for entry in fh_data.values():
            last = entry.get("last_checked")
            if not last:
                continue
            try:
                dt = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if dt < cutoff:
                continue
            s = entry.get("status", "ok")
            feed_summary[s] = feed_summary.get(s, 0) + 1
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    completed_at = latest_run.get("completed_at")
    last_run_age: float | None = None
    if completed_at:
        try:
            dt = datetime.fromisoformat(str(completed_at).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            last_run_age = (datetime.now(timezone.utc) - dt).total_seconds()
        except (ValueError, TypeError):
            last_run_age = None

    heartbeat_age: float | None = None
    heartbeat_path = BASE_DIR / _HEARTBEAT_PATH
    try:
        heartbeat_age = time.time() - heartbeat_path.stat().st_mtime
    except OSError:
        heartbeat_age = None

    def _corpus_size() -> int:
        try:
            return len(load_articles())
        except Exception:
            return 0

    # Briefing freshness is computed before status so a stale/frozen briefing
    # can degrade `status` (not just appear as an informational field). Never
    # raises — on any error the values stay None and status logic skips them.
    briefing_stale: bool | None = None
    briefing_age_hours: float | None = None
    try:
        from modules.briefing_health import check_briefing_freshness
        freshness = check_briefing_freshness(max_age_hours=_BRIEFING_STALE_HOURS)
        briefing_stale = freshness["stale"]
        briefing_age_hours = round(freshness["age_hours"], 2)
    except Exception:
        briefing_stale = None
        briefing_age_hours = None

    status, reasons = _compute_status(
        latest_run, feed_summary, last_run_age, heartbeat_age,
        briefing_stale=briefing_stale, briefing_age_hours=briefing_age_hours,
    )

    artifact_health = None
    try:
        from modules.artifact_health import check_artifact_health
        artifact_health = check_artifact_health(BASE_DIR / "data" / "output")
        if artifact_health["configured"] and not artifact_health["ok"]:
            reasons.extend(
                f"artifact_stale_{name}"
                for name in artifact_health["stale_capabilities"]
                if f"artifact_stale_{name}" not in reasons
            )
            reasons.extend(
                f"ai_capability_failing_{name}"
                for name in artifact_health["failing_capabilities"]
                if f"ai_capability_failing_{name}" not in reasons
            )
            if status == "ok":
                status = "degraded"
    except Exception as exc:
        logger.warning("Artifact health check failed: %s", exc)

    payload = {
        "status": status,
        "reasons": reasons,
        "uptime_s": int(time.time() - _SERVER_START),
        "last_run_at": completed_at,
        "last_run_age_s": int(last_run_age) if last_run_age is not None else None,
        "heartbeat_age_s": int(heartbeat_age) if heartbeat_age is not None else None,
        # articles_total is the SERVED CORPUS size — the same number
        # /api/articles reports — so the two endpoints can be compared
        # directly. It previously held the latest run's raw fetch count,
        # which made health look like it disagreed with the API by
        # thousands. Per-run counters keep their own explicit names.
        "articles_total": _corpus_size(),
        "last_run_fetched": latest_run.get("articles_fetched", 0),
        "articles_cyber": latest_run.get("cyber_articles", 0),
        "articles_enriched": latest_run.get("articles_enriched", 0),
        "analysis_failures": latest_run.get("analysis_failures", 0),
        "budget_exceeded": bool(latest_run.get("budget_exceeded", False)),
        "api_cost_today_usd": latest_run.get("api_cost_today", 0),
        "feed_health": feed_summary,
        "ai_artifacts": artifact_health,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    payload["briefing_stale"] = briefing_stale
    payload["briefing_age_hours"] = (
        briefing_age_hours
        if briefing_age_hours is not None and math.isfinite(briefing_age_hours)
        else None
    )
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def render_page():
    """Return the built frontend shell without embedding the article corpus."""
    now = time.time()
    key = "__rendered_page__"
    entry = _cache.get(key)
    if entry and (now - entry[0]) < CACHE_TTL:
        return entry[1]

    body = read_cached(FRONTEND_DIST / "index.html")
    with _cache_lock:
        _cache[key] = (now, body)
    return body


def resolve_frontend_asset(url_path: str) -> Path | None:
    """Resolve a built asset path while rejecting traversal and directories."""
    if not url_path.startswith("/assets/"):
        return None
    relative = Path(unquote(url_path).lstrip("/"))
    root = FRONTEND_DIST.resolve()
    candidate = (FRONTEND_DIST / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def load_ioc_items() -> list:
    """Load IOC (ThreatFox) items from the full article list."""
    articles = load_articles()
    return [a for a in articles if a.get("isDarkweb") and a.get("darkwebSource") == "threatfox"]


def build_openapi() -> bytes:
    """Return the stable public v1 API description."""
    paths = {
        "/api/v1/articles": {"get": {"summary": "List recent articles"}},
        "/api/v1/articles/{id}": {"get": {"summary": "Get one article"}},
        "/api/v1/briefings/latest": {"get": {"summary": "Get latest briefing"}},
        "/api/v1/briefings/{region}": {"get": {"summary": "Get regional briefing"}},
        "/api/v1/incidents": {"get": {"summary": "List incident clusters"}},
        "/api/v1/sources": {"get": {"summary": "List source coverage"}},
        "/api/v1/health": {"get": {"summary": "Get service health"}},
        "/api/v1/health/ai": {"get": {"summary": "Get AI artifact health"}},
        "/api/v1/health/feeds": {"get": {"summary": "Get feed health"}},
    }
    payload = {
        "openapi": "3.1.0",
        "info": {"title": "ThreatWatch API", "version": "1.0.0"},
        "paths": paths,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def build_sources() -> bytes:
    """Aggregate publisher coverage without exposing scraped content."""
    counts: dict[tuple[str, str], int] = collections.Counter()
    for article in load_articles():
        name = str(article.get("source_name") or "Unknown source")
        feed_url = str(article.get("source") or "")
        counts[(name, feed_url)] += 1
    sources = [
        {"name": name, "feed_url": feed_url, "article_count": count}
        for (name, feed_url), count in counts.most_common()
    ]
    return json.dumps(
        {"total": len(sources), "sources": sources},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")


def _first_param(params: dict, name: str) -> str:
    return str(params.get(name, [""])[0] or "").strip()


def _is_vulnerability_article(article: dict) -> bool:
    source = str(article.get("source") or "").lower()
    category = str(article.get("category") or "").lower()
    return bool(
        article.get("cve_ids")
        or source in {"nvd:cve", "https://vulners.com/rss.xml"}
        or any(term in category for term in ("vulnerab", "patch", "zero-day"))
    )


def _is_bulk_vulnerability_article(article: dict) -> bool:
    source = str(article.get("source") or "").lower()
    return source in {"nvd:cve", "https://vulners.com/rss.xml"}


def _matches_article_filters(article: dict, filters: dict[str, str]) -> bool:
    searchable = " ".join(
        str(article.get(field) or "")
        for field in ("title", "translated_title", "summary", "source_name", "category")
    ).casefold()
    if filters["q"] and filters["q"].casefold() not in searchable:
        return False
    for field in ("category", "region", "source"):
        expected = filters[field]
        actual = article.get("source_name") if field == "source" else article.get(field)
        if expected and str(actual or "").casefold() != expected.casefold():
            return False
    view = filters["view"].casefold()
    is_vulnerability = _is_vulnerability_article(article)
    if view == "vulnerabilities" and not is_vulnerability:
        return False
    kev_listed = article.get("kev_listed") or article.get("kevListed")
    if view == "news" and _is_bulk_vulnerability_article(article) and not kev_listed:
        return False
    return True


def filter_articles(articles: list[dict], params: dict) -> tuple[list[dict], dict[str, str]]:
    """Apply bounded public query filters without changing the stored corpus."""
    filters = {
        name: _first_param(params, name)
        for name in ("q", "category", "region", "source", "view")
    }
    filtered = [article for article in articles if _matches_article_filters(article, filters)]
    return filtered, filters


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
    "/api/briefing/na": {
        "file": BASE_DIR / "data" / "output" / "briefing_na.json",
        "content_type": "application/json; charset=utf-8",
    },
    "/api/briefing/emea": {
        "file": BASE_DIR / "data" / "output" / "briefing_emea.json",
        "content_type": "application/json; charset=utf-8",
    },
    "/api/briefing/apac": {
        "file": BASE_DIR / "data" / "output" / "briefing_apac.json",
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

UI_ROUTES = frozenset({
    "/", "/news", "/vulnerabilities", "/campaigns", "/watchlists",
    "/briefings", "/api-docs", "/system",
})


def _is_ui_route(path: str) -> bool:
    return path in UI_ROUTES or path.startswith("/news/")

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
    # Operational/metrics endpoints don't need cross-origin browser access;
    # leaving them on the wildcard CORS list handed any web page a detailed
    # map of pipeline internals (token spend, classifier accuracy, DB size).
    _RESTRICTED_CORS_PATHS = frozenset({
        "/api/health", "/api/v1/health", "/api/v1/health/ai",
        "/api/v1/health/feeds",
        "/api/watchlist", "/api/quality", "/api/groq-usage",
    })

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
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            logger.debug("Client disconnected before error response completed")

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
            global _gzip_memo
            memo_etag, memo_body = _gzip_memo
            if memo_etag == etag:
                body = memo_body
            else:
                body = gzip.compress(body, compresslevel=6)
                with _gzip_memo_lock:
                    _gzip_memo = (etag, body)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Encoding", "gzip")
        else:
            self.send_response(HTTPStatus.OK)

        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=30")
        self.send_header("ETag", etag)
        # NOTE: no Last-Modified header. The old one was stamped with the
        # response time on every request — always "now" — which is worse
        # than absent: it actively defeated If-Modified-Since validation.
        # ETag/If-None-Match carries conditional GETs correctly.
        self._send_security_headers()
        self._send_cors_headers()
        self.end_headers()
        if not head_only:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                logger.debug("Client disconnected before response completed")

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
        client_ip = _get_client_ip(self)
        if _is_rate_limited(client_ip):
            self._send_error_json(HTTPStatus.TOO_MANY_REQUESTS, "Rate limit exceeded")
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/api/feedback":
            # Classifier feedback — analysts flag misclassified articles so
            # accuracy can be tracked and keyword patterns tuned. FAIL CLOSED:
            # if WATCHLIST_TOKEN isn't configured, refuse writes entirely so
            # the endpoint can't be used to poison the dataset anonymously.
            if not WATCHLIST_TOKEN:
                self._send_error_json(HTTPStatus.FORBIDDEN,
                                      "Feedback writes disabled: set WATCHLIST_TOKEN to enable")
                return
            auth = self.headers.get("Authorization", "")
            if not hmac.compare_digest(auth.encode(), f"Bearer {WATCHLIST_TOKEN}".encode()):
                self._send_error_json(HTTPStatus.UNAUTHORIZED, "Invalid or missing authorization token")
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                if length <= 0:
                    self._send_error_json(HTTPStatus.LENGTH_REQUIRED, "Content-Length required")
                    return
                if length > 16384:  # 16 KB max
                    self._send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Payload too large")
                    return
                raw = self.rfile.read(length)
                data = json.loads(raw)
                article_hash = str(data.get("article_hash", "")).strip()[:128]
                correct_category = str(data.get("correct_category", "")).strip()[:128]
                note = str(data.get("note", "")).strip()[:512]
                if not article_hash or not correct_category:
                    self._send_error_json(HTTPStatus.BAD_REQUEST, "Missing article_hash or correct_category")
                    return
                record = {
                    "article_hash": article_hash,
                    "correct_category": correct_category,
                    "note": note,
                    "received_at": datetime.now(timezone.utc).isoformat(),
                    "source_ip": _get_client_ip(self),
                }
                feedback_path = BASE_DIR / "data" / "state" / "feedback.jsonl"
                feedback_path.parent.mkdir(parents=True, exist_ok=True)
                with open(feedback_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
                body = json.dumps({"ok": True}).encode()
            except (json.JSONDecodeError, ValueError):
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid JSON payload")
                return
            except OSError as exc:
                logger.error("Feedback write failed: %s", exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Write failed")
                return
            self._send_body("application/json; charset=utf-8", body, False)
            return

        if path == "/api/watchlist":
            if not WATCHLIST_WRITE_ENABLED:
                self._send_error_json(HTTPStatus.FORBIDDEN,
                                      "Watchlist write not enabled on this instance. "
                                      "Set WATCHLIST_WRITE_ENABLED=true to allow.")
                return
            # Fail-closed: require a token even if operator forgot to set one
            if not WATCHLIST_TOKEN:
                self._send_error_json(HTTPStatus.FORBIDDEN,
                                      "Watchlist writes require WATCHLIST_TOKEN to be set")
                return
            auth = self.headers.get("Authorization", "")
            if not hmac.compare_digest(auth.encode(), f"Bearer {WATCHLIST_TOKEN}".encode()):
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
        client_ip = _get_client_ip(self)
        if _is_rate_limited(client_ip):
            self._send_error_json(HTTPStatus.TOO_MANY_REQUESTS,
                                  "Rate limit exceeded — max 120 requests per minute")
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)

        v1_aliases = {
            "/api/v1/articles": "/api/articles",
            "/api/v1/briefings/latest": "/api/briefing",
            "/api/v1/briefings/na": "/api/briefing/na",
            "/api/v1/briefings/emea": "/api/briefing/emea",
            "/api/v1/briefings/apac": "/api/briefing/apac",
            "/api/v1/incidents": "/api/clusters",
            "/api/v1/health": "/api/health",
        }

        if path.startswith("/api/v1/articles/"):
            article_id = path.removeprefix("/api/v1/articles/")
            valid_id = article_id.replace("-", "").replace("_", "").isalnum()
            if not article_id or len(article_id) > 128 or not valid_id:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid article id")
                return
            article = next(
                (item for item in load_articles() if str(item.get("hash")) == article_id),
                None,
            )
            if article is None:
                self._send_error_json(HTTPStatus.NOT_FOUND, "Article not found")
                return
            safe_article = {k: v for k, v in article.items() if k != "full_content"}
            body = json.dumps(
                safe_article, ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        if path == "/api/v1/health/ai":
            from modules.artifact_health import check_artifact_health
            body = json.dumps(
                check_artifact_health(BASE_DIR / "data" / "output"),
                ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        if path == "/api/v1/health/feeds":
            from modules.feed_health import get_health_json
            body = json.dumps(
                get_health_json(), ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        if path == "/api/v1/sources":
            self._send_body(
                "application/json; charset=utf-8", build_sources(), head_only,
            )
            return

        if path == "/api/v1/openapi.json":
            self._send_body(
                "application/json; charset=utf-8", build_openapi(), head_only,
            )
            return

        asset = resolve_frontend_asset(path)
        if asset is not None:
            content_type = mimetypes.guess_type(asset.name)[0] or "application/octet-stream"
            self._send_body(content_type, read_cached(asset), head_only)
            return

        path = v1_aliases.get(path, path)

        # UI routes all return the same application shell. Data is fetched
        # through bounded API requests instead of being embedded in HTML.
        if _is_ui_route(path):
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

        # Route: /api/since?ts=<iso>&limit=N — incremental feed refresh. Returns
        # only articles whose `timestamp` (ingest time, not publish time) is
        # strictly newer than the supplied cursor. Cheap for polling clients
        # (webhooks, CLI, Slackbot) that currently refetch the whole 7-day
        # window on every tick.
        if path == "/api/since":
            try:
                from modules.date_utils import parse_datetime
                qs = parse_qs(parsed.query)
                ts_raw = (qs.get("ts", [""])[0] or "").strip()
                # Clients routinely pass next_cursor back without URL-encoding
                # the timezone "+" (the documented Logic App recipe does);
                # query decoding turns it into a space. An ISO timestamp never
                # legitimately contains a space before the offset, so undo it.
                if " " in ts_raw and "+" not in ts_raw:
                    ts_raw = ts_raw.replace(" ", "+")
                limit_raw = (qs.get("limit", ["200"])[0] or "200").strip()
                try:
                    limit = max(1, min(int(limit_raw), 1000))
                except ValueError:
                    self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid limit")
                    return
                cursor = parse_datetime(ts_raw) if ts_raw else None
                if ts_raw and cursor is None:
                    self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid ts (expected ISO 8601 or RFC 2822)")
                    return

                articles = load_articles()
                matched = []
                newest_ts: datetime | None = None
                for a in articles:
                    art_dt = parse_datetime(a.get("timestamp")) or parse_datetime(a.get("published"))
                    if art_dt is None:
                        continue
                    if cursor is not None and art_dt <= cursor:
                        continue
                    if newest_ts is None or art_dt > newest_ts:
                        newest_ts = art_dt
                    matched.append((art_dt, a))

                # Oldest-first chronological pagination. The old behavior
                # sliced newest-first but advanced next_cursor to the newest
                # matched timestamp, so every unreturned (older) article fell
                # behind the cursor and was silently lost to paging clients —
                # exactly the alert-pipeline integration this endpoint serves.
                # Oldest-first + cursor = last RETURNED item walks the stream
                # forward losslessly: anything unreturned is newer than the
                # cursor and arrives on the next poll.
                matched.sort(key=lambda pair: pair[0])
                sliced = matched[:limit]
                payload_articles = [
                    {k: v for k, v in a.items() if k != "full_content"}
                    for _, a in sliced
                ]
                if sliced:
                    next_cursor = sliced[-1][0].isoformat()
                else:
                    next_cursor = ts_raw or None
                payload = {
                    "count": len(payload_articles),
                    "total_new": len(matched),
                    "truncated": len(matched) > len(sliced),
                    "next_cursor": next_cursor,
                    "articles": payload_articles,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
                body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            except Exception as exc:
                logger.error("/api/since error: %s", exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Since query failed")
                return
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Route: /api/campaigns — list persistent threat campaigns with
        # optional ?status=active|dormant|archived filter.
        if path == "/api/campaigns":
            try:
                from modules.campaign_tracker import list_campaigns
                qs = parse_qs(parsed.query)
                status = (qs.get("status", [None])[0] or "").strip() or None
                if status and status not in ("active", "dormant", "archived", "unknown"):
                    self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid status filter")
                    return
                items = list_campaigns(status=status)
                payload = {
                    "total": len(items),
                    "status_filter": status,
                    "campaigns": items,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
                body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            except Exception as exc:
                logger.error("Campaigns list error: %s", exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Campaigns list failed")
                return
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Route: /api/campaign/<id> — a single campaign's persistent record
        # with a first_reported block and the matched articles sorted
        # ascending by publish date, so the earliest outlet wins attribution.
        if path.startswith("/api/campaign/"):
            campaign_id = path[len("/api/campaign/"):]
            if not _CAMPAIGN_ID_RE.fullmatch(campaign_id):
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid campaign id")
                return
            try:
                from modules.campaign_tracker import get_campaign
                data = get_campaign(campaign_id)
                if data is None:
                    self._send_error_json(HTTPStatus.NOT_FOUND, "Campaign not found")
                    return
                enriched = _enrich_campaign_with_articles(data)
                body = json.dumps(enriched, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            except Exception as exc:
                logger.error("Campaign view error: %s", exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Campaign view failed")
                return
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Route: /api/cve/<ID> — all articles referencing the given CVE, sorted
        # by published date ascending so the earliest outlet wins the
        # "first reported by" slot. Includes EPSS score if any article carries
        # one, and a summary count.
        if path.startswith("/api/cve/"):
            cve_id = path[len("/api/cve/"):].upper()
            if not _CVE_PATH_RE.fullmatch(cve_id):
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid CVE ID")
                return
            try:
                body = _build_cve_view(cve_id)
            except Exception as exc:
                logger.error("CVE view error for %s: %s", cve_id, exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "CVE view failed")
                return
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Route: /api/groq-usage — per-key / per-caller LLM usage today.
        # Reads data/state/groq_usage.json populated by modules/groq_usage.
        # Useful for spotting which Groq key is closest to its daily cap and
        # which caller (briefing / classify / summaries …) is eating budget.
        if path == "/api/groq-usage":
            try:
                from modules.groq_usage import get_usage_summary
                payload = get_usage_summary()
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            except Exception as exc:
                logger.error("Groq usage error: %s", exc)
                self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Groq usage failed")
                return
            self._send_body("application/json; charset=utf-8", body, head_only)
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
                from modules.feed_health import get_health_json, signal_scores
                articles = load_articles()
                from collections import Counter
                cat_counts = Counter(a.get("category", "Unknown") for a in articles)
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
                    # Signal score per feed: combines success rate, avg
                    # entries per fetch, and freshness status into 0-100 so
                    # analysts can sort / threshold noisy feeds.
                    "feed_signal_scores": signal_scores(),
                    "classifier_feedback": _feedback_summary(),
                    "sqlite": _db_stats_safe(),
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
                articles, active_filters = filter_articles(load_articles(), params)
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
                limit = int(params.get("limit", [50])[0])
            except (ValueError, TypeError):
                self._send_error_json(HTTPStatus.BAD_REQUEST, "limit must be an integer")
                return

            total = len(articles)
            offset = max(0, min(offset, total))
            limit = max(1, min(limit, 100))
            page = articles[offset:offset + limit]

            # Strip scraped full text — every other article endpoint does;
            # this one leaked it, inflating responses ~10x and exposing
            # full scraped bodies to any caller.
            page = [
                {k: v for k, v in a.items() if k != "full_content"}
                for a in page
            ]

            result = {
                "articles": page,
                "total": total,
                "offset": offset,
                "limit": limit,
                "has_more": (offset + len(page)) < total,
                "filters": active_filters,
            }

            body = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self._send_body("application/json; charset=utf-8", body, head_only)
            return

        # Route: /api/watchlist — GET returns current watchlist + vendor suggest-list
        if path == "/api/watchlist":
            if WATCHLIST_TOKEN:
                auth = self.headers.get("Authorization", "")
                if not hmac.compare_digest(auth.encode(), f"Bearer {WATCHLIST_TOKEN}".encode()):
                    self._send_error_json(HTTPStatus.UNAUTHORIZED, "Invalid or missing authorization token")
                    return
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
    # SSRF guard covers watchlist rehydration / any future outbound fetches.
    from modules.safe_http import install_ssrf_guard
    install_ssrf_guard()
    server = ThreadedHTTPServer(("0.0.0.0", PORT), ThreatWatchHandler)
    logger.info("ThreatWatch v2.0 server starting on http://0.0.0.0:%d", PORT)
    logger.info("Base directory: %s", BASE_DIR)
    logger.info("Frontend shell enabled; intelligence loads through bounded API requests")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
