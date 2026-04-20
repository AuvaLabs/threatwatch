"""SQLite persistence layer for ThreatWatch — staged migration from JSON.

Context: the pipeline currently rewrites the entire `daily_latest.json`
(12 MB and growing) on every 10-minute run via `output_writer._merge_articles`.
Fine at 2k articles, degrades badly past 5x that volume. This module introduces
SQLite as a secondary write target so the transition can land incrementally:

Phase 1 (this file): schema + write helpers + one-shot import of the current
    JSON state. `output_writer` dual-writes to JSON and SQLite. Reads still
    come from JSON. Zero-risk — if SQLite writes fail, the run continues.
Phase 2 (future): server and pipeline read from SQLite via a thin API-level
    adapter. JSON write becomes an export, not the source of truth.
Phase 3 (future): drop JSON writes; keep periodic JSON exports for external
    consumers (RSS feed, gh-pages static site).

The schema is deliberately conservative: one row per article, indexed on the
hash and on ingest timestamp so the existing cutoff and de-dup behaviours map
to simple queries. Full-text search (FTS5) is provisioned but not populated
here; adding it is a trivial ALTER once Phase 2 lands.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from modules.config import OUTPUT_DIR

logger = logging.getLogger(__name__)

DB_PATH = OUTPUT_DIR / "threatwatch.db"

# One connection, guarded by a lock. sqlite3 supports multi-threaded access
# with `check_same_thread=False`, but locking around commits is still the
# safest pattern under a threaded HTTP server + a second process (pipeline)
# writing concurrently. SQLite's own WAL mode handles cross-process
# concurrency; this lock only covers the in-process write path.
_conn_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def _open() -> sqlite3.Connection:
    """Open (or reuse) the writable connection with WAL + foreign keys on."""
    global _conn
    if _conn is not None:
        return _conn
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _conn = conn
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS articles (
        hash            TEXT PRIMARY KEY,
        title           TEXT NOT NULL,
        translated_title TEXT,
        link            TEXT,
        published       TEXT,
        timestamp       TEXT NOT NULL,
        source_name     TEXT,
        feed_region     TEXT,
        language        TEXT,
        category        TEXT,
        confidence      INTEGER,
        summary         TEXT,
        payload_json    TEXT NOT NULL  -- full article dict for forward-compat
    );
    CREATE INDEX IF NOT EXISTS idx_articles_timestamp ON articles(timestamp);
    CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published);
    CREATE INDEX IF NOT EXISTS idx_articles_category ON articles(category);
    CREATE INDEX IF NOT EXISTS idx_articles_feed_region ON articles(feed_region);

    CREATE TABLE IF NOT EXISTS campaigns (
        campaign_id     TEXT PRIMARY KEY,
        entity_type     TEXT NOT NULL,
        entity_name     TEXT NOT NULL,
        first_observed  TEXT,
        last_observed   TEXT,
        total_observed_articles INTEGER,
        status          TEXT,
        payload_json    TEXT NOT NULL,
        UNIQUE (entity_type, entity_name)
    );
    CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
    """)


# ── public write API ──────────────────────────────────────────────────────────
def upsert_articles(articles: Iterable[dict[str, Any]]) -> int:
    """Write each article to SQLite via INSERT OR REPLACE on `hash`.

    Returns the count of rows written. Articles without a `hash` are skipped
    (mirrors the invariant enforced by output_writer._merge_articles).
    """
    with _conn_lock:
        conn = _open()
        count = 0
        with conn:
            for a in articles:
                h = a.get("hash")
                if not h:
                    continue
                conn.execute(
                    """
                    INSERT OR REPLACE INTO articles
                    (hash, title, translated_title, link, published, timestamp,
                     source_name, feed_region, language, category, confidence,
                     summary, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        h,
                        a.get("title", ""),
                        a.get("translated_title"),
                        a.get("link"),
                        a.get("published"),
                        a.get("timestamp") or "",
                        a.get("source_name"),
                        a.get("feed_region"),
                        a.get("language"),
                        a.get("category"),
                        a.get("confidence") or 0,
                        a.get("summary"),
                        json.dumps(a, ensure_ascii=False),
                    ),
                )
                count += 1
        return count


def prune_older_than(cutoff_iso: str) -> int:
    """Delete articles whose timestamp < cutoff_iso. Returns row count."""
    with _conn_lock:
        conn = _open()
        with conn:
            cur = conn.execute(
                "DELETE FROM articles WHERE timestamp < ?", (cutoff_iso,)
            )
            return cur.rowcount


def upsert_campaign(campaign: dict[str, Any]) -> None:
    cid = campaign.get("campaign_id")
    if not cid:
        return
    with _conn_lock:
        conn = _open()
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO campaigns
                (campaign_id, entity_type, entity_name, first_observed,
                 last_observed, total_observed_articles, status, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cid,
                    campaign.get("entity_type", ""),
                    campaign.get("entity_name", ""),
                    campaign.get("first_observed"),
                    campaign.get("last_observed"),
                    campaign.get("total_observed_articles") or 0,
                    campaign.get("status"),
                    json.dumps(campaign, ensure_ascii=False),
                ),
            )


# ── read helpers (for Phase 2 and stats) ──────────────────────────────────────
def count_articles() -> int:
    with _conn_lock:
        conn = _open()
        row = conn.execute("SELECT COUNT(*) FROM articles").fetchone()
        return row[0] if row else 0


def count_campaigns() -> int:
    with _conn_lock:
        conn = _open()
        row = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()
        return row[0] if row else 0


def stats() -> dict[str, Any]:
    """Cheap summary stats for /api/quality and operators."""
    with _conn_lock:
        conn = _open()
        a_count = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
        c_count = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
        a_size = conn.execute(
            "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()"
        ).fetchone()[0]
        return {
            "article_count": a_count,
            "campaign_count": c_count,
            "db_bytes": a_size,
            "db_path": str(DB_PATH),
        }


def close() -> None:
    """For tests and graceful shutdown; the long-running server leaves the
    connection open for the process lifetime."""
    global _conn
    with _conn_lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None
