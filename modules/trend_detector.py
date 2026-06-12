"""Threat trend detection engine.

Tracks keyword/category/actor frequency over time and detects spikes
that indicate emerging threats. Persists trend data to flat-file JSON.

A "spike" is when the current period's count exceeds the rolling average
by a configurable multiplier (default: 2x = double the normal rate).
"""

import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from modules.config import STATE_DIR

logger = logging.getLogger(__name__)

TREND_FILE = STATE_DIR / "trends.json"
TREND_HISTORY_DAYS = 30  # How many days of history to keep

# Spike detection: current period count must be >= multiplier * rolling average
_SPIKE_MULTIPLIER = 2.0
_MIN_COUNT_FOR_SPIKE = 3  # Don't flag spikes for very low counts

# Keywords to track for trend detection (beyond categories)
_TRACKED_KEYWORDS = {
    # Ransomware groups
    "LockBit": re.compile(r"\blockbit\b", re.I),
    "BlackCat/ALPHV": re.compile(r"\b(blackcat|alphv)\b", re.I),
    "Cl0p": re.compile(r"\b(cl0p|clop)\b", re.I),
    "RansomHub": re.compile(r"\bransomhub\b", re.I),
    "Akira": re.compile(r"\bakira\s+ransom", re.I),
    "Play": re.compile(r"\bplay\s+ransomware", re.I),
    "Qilin": re.compile(r"\bqilin\b", re.I),
    # APT groups
    "APT28/Fancy Bear": re.compile(r"\b(apt28|fancy\s*bear|forest\s*blizzard)\b", re.I),
    "APT29/Cozy Bear": re.compile(r"\b(apt29|cozy\s*bear|midnight\s*blizzard)\b", re.I),
    "Lazarus": re.compile(r"\blazarus\b", re.I),
    "Volt Typhoon": re.compile(r"\bvolt\s*typhoon\b", re.I),
    "Salt Typhoon": re.compile(r"\bsalt\s*typhoon\b", re.I),
    "Scattered Spider": re.compile(r"\bscattered\s*spider\b", re.I),
    "Sandworm": re.compile(r"\bsandworm\b", re.I),
    # Attack types
    "Zero-Day": re.compile(r"zero[\s-]?day|0[\s-]?day", re.I),
    "Supply Chain": re.compile(r"supply[\s-]chain\s+(attack|compromise)", re.I),
    "DDoS": re.compile(r"\bddos\b", re.I),
    "Phishing Campaign": re.compile(r"phishing\s+campaign", re.I),
    "BEC/Wire Fraud": re.compile(r"\bbec\b|business\s+email\s+compromise|wire\s+fraud", re.I),
    # Technologies under attack
    "Microsoft": re.compile(r"\b(microsoft|windows|exchange|outlook|azure)\b.*\b(vuln|exploit|attack|breach|zero.day)", re.I),
    "Cisco": re.compile(r"\bcisco\b.*\b(vuln|exploit|attack|advisory)", re.I),
    "Fortinet": re.compile(r"\bfortinet\b.*\b(vuln|exploit|attack|advisory)", re.I),
    "VMware": re.compile(r"\bvmware\b.*\b(vuln|exploit|attack)", re.I),
    "Ivanti": re.compile(r"\bivanti\b.*\b(vuln|exploit|attack|advisory)", re.I),
    # Sectors
    "Healthcare": re.compile(r"(hospital|healthcare|medical|patient\s+data)\s*.{0,20}(attack|breach|ransom|hack)", re.I),
    "Financial": re.compile(r"(bank|financial|fintech)\s*.{0,20}(attack|breach|hack|fraud)", re.I),
    "Government": re.compile(r"(government|federal|municipal|city)\s*.{0,20}(attack|breach|hack)", re.I),
    "Education": re.compile(r"(university|school|college|education)\s*.{0,20}(attack|breach|ransom|hack)", re.I),
}


def _load_trends() -> dict:
    if TREND_FILE.exists():
        try:
            return json.loads(TREND_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"daily_counts": {}, "generated_at": None}


def _save_trends(data: dict) -> None:
    TREND_FILE.parent.mkdir(parents=True, exist_ok=True)
    TREND_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _prune_old_data(daily_counts: dict, max_days: int) -> dict:
    """Remove entries older than max_days."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max_days)).strftime("%Y-%m-%d")
    return {date: counts for date, counts in daily_counts.items() if date >= cutoff}


def update_trends(articles: list[dict[str, Any]]) -> dict:
    """Update trend data with articles from this pipeline run.

    Returns the current trend state including any detected spikes.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    trends = _load_trends()
    daily_counts = trends.get("daily_counts", {})

    # Initialize today's counts
    if today not in daily_counts:
        daily_counts[today] = {"categories": {}, "keywords": {}}

    today_data = daily_counts[today]

    # Count categories
    cat_counts = Counter(a.get("category", "Unknown") for a in articles)
    for cat, count in cat_counts.items():
        today_data["categories"][cat] = today_data["categories"].get(cat, 0) + count

    # Count tracked keywords
    for article in articles:
        text = " ".join(filter(None, [
            article.get("title", ""),
            article.get("summary", ""),
        ]))
        for keyword, pattern in _TRACKED_KEYWORDS.items():
            if pattern.search(text):
                today_data["keywords"][keyword] = today_data["keywords"].get(keyword, 0) + 1

    # Prune old data
    daily_counts = _prune_old_data(daily_counts, TREND_HISTORY_DAYS)
    daily_counts[today] = today_data

    # Detect spikes
    spikes = _detect_spikes(daily_counts, today)

    trends = {
        "daily_counts": daily_counts,
        "spikes": spikes,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    _save_trends(trends)

    if spikes:
        logger.warning(f"TREND SPIKES detected: {[s['keyword'] for s in spikes]}")
    else:
        logger.info("Trends: no spikes detected")

    return trends


def _detect_spikes(daily_counts: dict, today: str) -> list[dict]:
    """Detect keyword/category spikes by comparing today vs rolling average."""
    spikes = []
    dates = sorted(daily_counts.keys())

    if len(dates) < 3:
        return []  # Need at least 3 days of history

    today_data = daily_counts.get(today, {})
    history_dates = [d for d in dates if d != today][-14:]  # Last 14 days excluding today

    # Check categories
    for cat, today_count in today_data.get("categories", {}).items():
        if today_count < _MIN_COUNT_FOR_SPIKE:
            continue
        historical = [daily_counts[d].get("categories", {}).get(cat, 0) for d in history_dates]
        avg = sum(historical) / len(historical) if historical else 0
        if avg > 0 and today_count >= avg * _SPIKE_MULTIPLIER:
            spikes.append({
                "keyword": cat,
                "type": "category",
                "today_count": today_count,
                "avg_count": round(avg, 1),
                "spike_ratio": round(today_count / avg, 1),
            })

    # Check keywords
    for keyword, today_count in today_data.get("keywords", {}).items():
        if today_count < _MIN_COUNT_FOR_SPIKE:
            continue
        historical = [daily_counts[d].get("keywords", {}).get(keyword, 0) for d in history_dates]
        avg = sum(historical) / len(historical) if historical else 0
        if avg > 0 and today_count >= avg * _SPIKE_MULTIPLIER:
            spikes.append({
                "keyword": keyword,
                "type": "tracked_keyword",
                "today_count": today_count,
                "avg_count": round(avg, 1),
                "spike_ratio": round(today_count / avg, 1),
            })
        elif avg == 0 and today_count >= _MIN_COUNT_FOR_SPIKE:
            # New keyword appearing for the first time with significant count.
            # spike_ratio must stay JSON-safe: float("inf") serialises as the
            # bare token `Infinity`, which is invalid JSON — strict parsers
            # (browsers, jq) choke on the whole trends payload. A new
            # emergence has no meaningful ratio, so use the count itself as
            # the sort weight and flag it explicitly.
            spikes.append({
                "keyword": keyword,
                "type": "new_emergence",
                "new_emergence": True,
                "today_count": today_count,
                "avg_count": 0,
                "spike_ratio": float(today_count),
            })

    return sorted(spikes, key=lambda s: -s.get("spike_ratio", 0))


def get_trends_report() -> dict:
    """Return current trend data for API consumption."""
    trends = _load_trends()
    daily_counts = trends.get("daily_counts", {})

    if not daily_counts:
        return {"status": "no_data", "message": "No trend data collected yet."}

    dates = sorted(daily_counts.keys())

    # Aggregate keyword totals over last 7 and 30 days
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")

    week_keywords = Counter()
    month_keywords = Counter()
    week_categories = Counter()
    month_categories = Counter()

    for date, data in daily_counts.items():
        for keyword, count in data.get("keywords", {}).items():
            month_keywords[keyword] += count
            if date >= week_ago:
                week_keywords[keyword] += count
        for cat, count in data.get("categories", {}).items():
            month_categories[cat] += count
            if date >= week_ago:
                week_categories[cat] += count

    return {
        "status": "ok",
        "generated_at": trends.get("generated_at"),
        "date_range": {"start": dates[0], "end": dates[-1], "days": len(dates)},
        "spikes": trends.get("spikes", []),
        "top_keywords_7d": dict(week_keywords.most_common(20)),
        "top_keywords_30d": dict(month_keywords.most_common(20)),
        "categories_7d": dict(week_categories.most_common()),
        "categories_30d": dict(month_categories.most_common()),
        "daily_totals": {
            date: sum(data.get("categories", {}).values())
            for date, data in sorted(daily_counts.items())
        },
    }
