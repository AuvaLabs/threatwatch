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
from datetime import datetime, timezone, timedelta
from pathlib import Path

from modules.config import STATE_DIR

HEALTH_FILE = STATE_DIR / "feed_health.json"

_SUSPECT_DAYS = 3
_DEAD_DAYS    = 7
_STALE_DAYS   = 30


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


# ── core update ────────────────────────────────────────────────────────────

def record_fetch(url: str, success: bool, entry_count: int = 0) -> None:
    """Call after every feed fetch attempt to update health state.

    success=True  + entry_count>0  → feed is healthy, reset error counter
    success=True  + entry_count==0 → feed responded but had nothing new;
                                     don't penalise, just update last_checked
                                     and check for staleness
    success=False                  → actual error; increment error counter
    """
    data = load_health()
    now  = _now_iso()

    entry = data.get(url, {
        "url":                url,
        "consecutive_errors": 0,
        "first_error":        None,
        "last_success":       None,
        "last_checked":       None,
        "status":             "ok",
    })

    entry["last_checked"] = now

    if success and entry_count > 0:
        # Healthy fetch — reset all error state
        entry["consecutive_errors"] = 0
        entry["first_error"]        = None
        entry["last_success"]       = now
        entry["status"]             = "ok"

    elif success and entry_count == 0:
        # Quiet feed — HTTP ok, no articles in window; don't count as error
        # Check stale: if last_success exists and is old
        last_ok = entry.get("last_success")
        if last_ok and _days_since(last_ok) >= _STALE_DAYS:
            entry["status"] = "stale"
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
        logging.warning(
            f"DEAD FEED — {_days_since(entry['first_error']):.0f}d of errors: {url}"
        )
    elif entry["status"] == "suspect":
        logging.warning(
            f"SUSPECT FEED — {entry['consecutive_errors']} consecutive errors: {url}"
        )
    elif entry["status"] == "stale":
        last_ok = entry.get("last_success", "never")
        logging.warning(f"STALE FEED — no entries in 30d+ (last ok: {last_ok[:10] if last_ok else 'never'}): {url}")


# ── reporting ───────────────────────────────────────────────────────────────

def get_report() -> dict[str, list]:
    data = load_health()
    report: dict[str, list] = {"ok": [], "error": [], "suspect": [], "dead": [], "stale": []}
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
    if dead or suspect or stale:
        logging.warning(
            f"Feed health — ok:{ok} stale:{stale} suspect:{suspect} dead:{dead}"
        )
    else:
        logging.info(f"Feed health — all {ok} feeds ok")


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
