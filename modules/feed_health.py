"""Feed health tracking — persists per-feed error state across pipeline runs.

States per feed URL:
  ok      — last fetch returned entries (or is a new feed never yet fetched)
  error   — currently failing but < 3 days
  suspect — consecutive errors spanning 3–6 days
  dead    — consecutive errors spanning 7+ days
  stale   — no entries returned in 30+ days (HTTP ok but just silent)

Only actual HTTP errors / timeouts / parse failures increment the error counter.
A feed that returns HTTP 200 but has no articles within the cutoff window is NOT
an error — it's just quiet. That goes into the stale check instead.
"""

import json
import logging
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

from modules.config import STATE_DIR

HEALTH_FILE = STATE_DIR / "feed_health.json"

# record_fetch runs from 8 concurrent fetch threads. Without this lock, the
# load→mutate→save sequence lets two threads both read an old snapshot and
# each save their own mutation, silently dropping one of the updates. The lock
# is coarse (covers the whole read-modify-write) because save_health() already
# touches the filesystem — the contention cost is negligible compared to the
# disk write itself.
_health_lock = threading.Lock()

_SUSPECT_DAYS = 3
_DEAD_DAYS    = 7
_STALE_DAYS   = 30
# A feed that responds OK but has NEVER produced a single in-window article
# after this many fetches is flagged "silent" — typically a wrong URL that
# returns an empty/valid-but-irrelevant document. Without this, a feed with
# last_success=None could show "ok" forever (the stale check needs a prior
# success to compare against).
_SILENT_MIN_FETCHES = 10


# ── helpers ────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _utcnow().isoformat()


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


def _days_since(iso_str: str) -> float:
    return (_utcnow() - _parse_iso(iso_str)).total_seconds() / 86400


# ── persistence ────────────────────────────────────────────────────────────

def load_health() -> dict:
    if not HEALTH_FILE.exists():
        return {}
    try:
        return json.loads(HEALTH_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_health(data: dict) -> None:
    HEALTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    HEALTH_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _signal_score(entry: dict) -> float:
    """Compute a 0-100 signal score for a feed.

    Combines three dimensions:
    - Success rate (fetches_successful / fetches_total). A feed that
      intermittently 500s deserves a lower score even if its good fetches
      return content.
    - Productivity (avg entries per successful fetch, clamped to 1.0 at 20).
      A feed returning 20+ articles per run is at full productivity; fewer
      scales linearly.
    - Freshness (penalty for stale / dead / suspect status). A feed that
      has not returned in 30+ days is useless at any volume.

    Score is a simple multiplicative product scaled to 100 so analysts can
    sort / threshold without knowing the internals.
    """
    total = entry.get("fetches_total") or 0
    ok = entry.get("fetches_successful") or 0
    entries = entry.get("entries_total") or 0
    if total == 0:
        return 0.0
    success_rate = ok / total
    productivity = min((entries / ok) / 20.0, 1.0) if ok else 0.0
    status = entry.get("status", "ok")
    freshness = {"ok": 1.0, "error": 0.7, "suspect": 0.5, "stale": 0.3, "silent": 0.2, "dead": 0.1}.get(status, 0.5)
    return round(success_rate * productivity * freshness * 100.0, 1)


def signal_scores() -> list[dict]:
    """Return every tracked feed with its computed signal score, sorted desc."""
    data = load_health()
    items = [
        {
            "url": url,
            "status": entry.get("status", "ok"),
            "fetches_total": entry.get("fetches_total", 0),
            "fetches_successful": entry.get("fetches_successful", 0),
            "entries_total": entry.get("entries_total", 0),
            "avg_entries_per_fetch": (
                round((entry.get("entries_total", 0) / entry.get("fetches_successful", 1)), 2)
                if entry.get("fetches_successful") else 0.0
            ),
            "signal_score": _signal_score(entry),
        }
        for url, entry in data.items()
    ]
    items.sort(key=lambda i: i["signal_score"], reverse=True)
    return items


# ── core update ────────────────────────────────────────────────────────────

def record_fetch(url: str, success: bool, entry_count: int = 0) -> None:
    """Call after every feed fetch attempt to update health state.

    success=True  + entry_count>0  → feed is healthy, reset error counter
    success=True  + entry_count==0 → feed responded but had nothing new;
                                     don't penalise, just update last_checked
                                     and check for staleness
    success=False                  → actual error; increment error counter
    """
    with _health_lock:
        _record_fetch_locked(url, success, entry_count)


def _record_fetch_locked(url: str, success: bool, entry_count: int) -> None:
    data = load_health()
    now  = _now_iso()

    entry = data.get(url, {
        "url":                url,
        "consecutive_errors": 0,
        "first_error":        None,
        "last_success":       None,
        "last_checked":       None,
        "status":             "ok",
        # Volume metrics driving the signal score. All monotonic counters.
        "fetches_total":      0,
        "fetches_successful": 0,
        "entries_total":      0,
    })

    # Ensure older entries pick up the volume fields lazily (forwards-compat).
    entry.setdefault("fetches_total", 0)
    entry.setdefault("fetches_successful", 0)
    entry.setdefault("entries_total", 0)

    entry["last_checked"] = now
    entry["fetches_total"] += 1

    if success and entry_count > 0:
        # Healthy fetch — reset all error state
        entry["consecutive_errors"] = 0
        entry["first_error"]        = None
        entry["last_success"]       = now
        entry["status"]             = "ok"
        entry["fetches_successful"] += 1
        entry["entries_total"]      += entry_count

    elif success and entry_count == 0:
        # Quiet feed — HTTP ok, no articles in window; don't count as error
        # but DO count as a successful fetch so signal_score reflects volume.
        entry["fetches_successful"] += 1
        last_ok = entry.get("last_success")
        if last_ok and _days_since(last_ok) >= _STALE_DAYS:
            entry["status"] = "stale"
        elif last_ok is None and entry["fetches_successful"] >= _SILENT_MIN_FETCHES:
            # Responds but has NEVER yielded an article — wrong URL, empty
            # endpoint, or a challenge page that still parses as a feed.
            entry["status"] = "silent"
        # If it was already dead/suspect from errors, don't downgrade it here

    else:
        # Actual failure
        if entry["consecutive_errors"] == 0 or not entry.get("first_error"):
            entry["first_error"] = now
        entry["consecutive_errors"] += 1

        error_days = _days_since(entry["first_error"])
        if error_days >= _DEAD_DAYS:
            entry["status"] = "dead"
        elif error_days >= _SUSPECT_DAYS:
            entry["status"] = "suspect"
        else:
            entry["status"] = "error"

    data[url] = entry
    save_health(data)

    # Warn on degraded state
    if entry["status"] == "dead":
        logger.warning(
            f"DEAD FEED — {_days_since(entry['first_error']):.0f}d of errors: {url}"
        )
    elif entry["status"] == "suspect":
        logger.warning(
            f"SUSPECT FEED — {entry['consecutive_errors']} consecutive errors: {url}"
        )
    elif entry["status"] == "stale":
        last_ok = entry.get("last_success", "never")
        logger.warning(f"STALE FEED — no entries in 30d+ (last ok: {last_ok[:10] if last_ok else 'never'}): {url}")
    elif entry["status"] == "silent":
        logger.warning(
            f"SILENT FEED — responded {entry['fetches_successful']} times, never one article: {url}"
        )


def prune_unconfigured(active_urls) -> int:
    """Drop health entries for feeds no longer present in the YAML config.

    Removed feeds otherwise linger in the state file forever and inflate the
    dead/error counts that /api/health reports — production showed 11 "dead"
    feeds of which several had been deliberately removed from the config.
    Returns the number of entries pruned.
    """
    active = set(active_urls)
    with _health_lock:
        data = load_health()
        stale_keys = [u for u in data if u not in active]
        if not stale_keys:
            return 0
        for u in stale_keys:
            del data[u]
        save_health(data)
    logger.info("Feed health: pruned %d unconfigured feed entries", len(stale_keys))
    return len(stale_keys)


# ── reporting ───────────────────────────────────────────────────────────────

def get_report() -> dict[str, list]:
    data = load_health()
    report: dict[str, list] = {"ok": [], "error": [], "suspect": [], "dead": [], "stale": [], "silent": []}
    for entry in data.values():
        status = entry.get("status", "ok")
        report.setdefault(status, []).append(entry)
    return report


def log_health_summary() -> None:
    """Write a one-line summary to the pipeline log."""
    report = get_report()
    dead    = len(report.get("dead", []))
    suspect = len(report.get("suspect", []))
    stale   = len(report.get("stale", []))
    ok      = len(report.get("ok", []))
    error   = len(report.get("error", []))
    silent  = len(report.get("silent", []))
    if dead or suspect or stale or silent:
        logger.warning(
            f"Feed health — ok:{ok} error:{error} stale:{stale} "
            f"suspect:{suspect} dead:{dead} silent:{silent}"
        )
        for entry in report.get("dead", []):
            logger.warning(f"  DEAD: {entry.get('url', '?')[:70]}")
        for entry in report.get("suspect", []):
            logger.warning(f"  SUSPECT: {entry.get('url', '?')[:70]}")
    else:
        logger.info(f"Feed health — all {ok} feeds ok")


def get_health_json() -> dict:
    """Return health data as a JSON-serializable dict for the API."""
    report = get_report()
    return {
        "total_tracked": sum(len(v) for v in report.values()),
        "ok": len(report.get("ok", [])),
        "error": len(report.get("error", [])),
        "suspect": len(report.get("suspect", [])),
        "dead": len(report.get("dead", [])),
        "stale": len(report.get("stale", [])),
        "silent": len(report.get("silent", [])),
        "dead_feeds": [
            {"url": e.get("url", ""), "errors": e.get("consecutive_errors", 0),
             "last_success": str(e.get("last_success", "never"))[:10]}
            for e in report.get("dead", [])
        ],
        "suspect_feeds": [
            {"url": e.get("url", ""), "errors": e.get("consecutive_errors", 0)}
            for e in report.get("suspect", [])
        ],
    }


def print_report() -> None:
    """Human-readable report for manual runs."""
    report = get_report()
    total  = sum(len(v) for v in report.values())
    sep    = "=" * 62
    print(f"\n{sep}")
    print(f"FEED HEALTH REPORT  {_now_iso()[:10]}")
    print(sep)
    print(f"  Total tracked : {total}")
    print(f"  OK            : {len(report['ok'])}")
    print(f"  Stale (30d+)  : {len(report.get('stale', []))}")
    print(f"  Suspect (3d+) : {len(report.get('suspect', []))}")
    print(f"  Dead (7d+)    : {len(report.get('dead', []))}")
    print(f"  Error (<3d)   : {len(report.get('error', []))}")

    for status in ("dead", "suspect", "stale", "error"):
        entries = report.get(status, [])
        if not entries:
            continue
        print(f"\n  [{status.upper()}]")
        for e in sorted(entries, key=lambda x: x.get("consecutive_errors", 0), reverse=True):
            errs   = e.get("consecutive_errors", 0)
            last_ok = (e.get("last_success") or "never")[:10]
            print(f"    {errs:>3} errors | last ok: {last_ok} | {e['url']}")

    print(f"{sep}\n")


if __name__ == "__main__":
    print_report()
