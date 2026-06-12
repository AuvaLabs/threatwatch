"""ThreatWatch Feed Health Audit.

Compares configured feeds against actual article data to identify:
- Feeds configured but producing zero articles (silent failures)
- Feeds producing disproportionate volume (possible historic content)
- Coverage gaps by category/region
- Feed reliability assessment

Usage:
    python scripts/audit_feed_health.py [--json]
"""

import json
import sys
import yaml
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

CONFIG_DIR = Path(__file__).parent.parent / "config"
DATA_DIR = Path(__file__).parent.parent / "data"


def load_feeds():
    """Load all configured feed URLs from YAML configs."""
    feeds = {}
    for yaml_file in ["feeds_native.yaml", "feeds_google.yaml", "feeds_bing.yaml"]:
        path = CONFIG_DIR / yaml_file
        if not path.exists():
            continue
        with open(path) as f:
            entries = yaml.safe_load(f) or []
        for entry in entries:
            if isinstance(entry, dict) and entry.get("url"):
                feeds[entry["url"]] = {
                    "config_file": yaml_file,
                    "category": entry.get("category", ""),
                    "region": entry.get("region", "Global"),
                }
    return feeds


def load_articles(path=None):
    if path is None:
        path = DATA_DIR / "output" / "daily_latest.json"
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_feed_health():
    path = DATA_DIR / "state" / "feed_health.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def audit_feeds(configured_feeds, articles, health_data):
    findings = []
    stats = {}

    # Count articles per source
    source_counts = Counter(a.get("source", "") for a in articles)


    # Which configured feeds produced articles?
    active_feeds = set()
    for url in configured_feeds:
        if source_counts.get(url, 0) > 0:
            active_feeds.add(url)

    # Which configured feeds produced zero articles?
    silent_feeds = []
    for url, meta in configured_feeds.items():
        if url not in active_feeds:
            health = health_data.get(url, {})
            silent_feeds.append({
                "url": url,
                "config": meta["config_file"],
                "region": meta["region"],
                "health_status": health.get("status", "unknown"),
                "last_success": str(health.get("last_success", "never"))[:10],
            })

    stats["configured_feeds"] = len(configured_feeds)
    stats["active_feeds"] = len(active_feeds)
    stats["silent_feeds"] = len(silent_feeds)
    stats["active_rate_pct"] = round(len(active_feeds) / len(configured_feeds) * 100, 1) if configured_feeds else 0

    if silent_feeds:
        # Group by config file
        by_config = defaultdict(list)
        for f in silent_feeds:
            by_config[f["config"]].append(f)

        findings.append({
            "severity": "HIGH" if len(silent_feeds) > len(configured_feeds) * 0.3 else "MEDIUM",
            "issue": f"{len(silent_feeds)} configured feeds produced zero articles",
            "detail": f"Feed activity rate: {stats['active_rate_pct']}%. "
                      f"Silent feeds by config: {dict((k, len(v)) for k, v in by_config.items())}",
            "samples": [f"{f['url'][:70]} ({f['config']}, {f['health_status']})" for f in silent_feeds[:15]],
        })

    # Disproportionate sources (>8% of non-darkweb articles)
    non_dw = [a for a in articles if not a.get("darkweb")]
    non_dw_total = len(non_dw)
    non_dw_counts = Counter(a.get("source", "") for a in non_dw)
    dominant = [(s, n) for s, n in non_dw_counts.most_common(10)
                if n > non_dw_total * 0.08]
    if dominant:
        findings.append({
            "severity": "HIGH",
            "issue": "Disproportionate feed volume",
            "detail": f"Feeds producing >8% of non-darkweb articles (total: {non_dw_total}):",
            "samples": [f"{s[:70]}: {n} articles ({n/non_dw_total*100:.1f}%)" for s, n in dominant],
        })

    # Coverage gap analysis: regions without native feeds
    feed_regions = Counter(m["region"] for m in configured_feeds.values())
    article_regions = Counter(a.get("feed_region", "Global") for a in articles)
    stats["feed_regions"] = dict(feed_regions.most_common())
    stats["article_regions_top10"] = dict(article_regions.most_common(10))

    # Category coverage: which CATEGORIES have articles from native feeds vs only Google/Bing?
    cat_by_feed_type = defaultdict(lambda: {"native": 0, "google": 0, "bing": 0, "darkweb": 0, "other": 0})
    for a in articles:
        cat = a.get("category", "Unknown")
        source = a.get("source", "")
        if a.get("darkweb"):
            cat_by_feed_type[cat]["darkweb"] += 1
        elif "google.com" in source:
            cat_by_feed_type[cat]["google"] += 1
        elif "bing.com" in source:
            cat_by_feed_type[cat]["bing"] += 1
        elif source in configured_feeds and configured_feeds[source]["config_file"] == "feeds_native.yaml":
            cat_by_feed_type[cat]["native"] += 1
        else:
            cat_by_feed_type[cat]["other"] += 1

    # Categories with zero native feed articles (dependent only on search engines)
    search_only_cats = []
    for cat, counts in cat_by_feed_type.items():
        if counts["native"] == 0 and counts["darkweb"] == 0 and (counts["google"] + counts["bing"]) > 0:
            search_only_cats.append((cat, counts["google"] + counts["bing"]))

    if search_only_cats:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Categories with zero native feed coverage",
            "detail": "These categories have articles only from Google/Bing searches — "
                      "no primary source validation:",
            "samples": [f"{cat}: {n} articles (search-only)" for cat, n in
                        sorted(search_only_cats, key=lambda x: -x[1])],
        })

    stats["category_source_breakdown"] = {
        cat: dict(counts) for cat, counts in sorted(cat_by_feed_type.items())
    }

    # Feed health summary (if data exists)
    if health_data:
        health_summary = Counter(e.get("status", "unknown") for e in health_data.values())
        stats["health_summary"] = dict(health_summary)
        dead = [e for e in health_data.values() if e.get("status") == "dead"]
        if dead:
            findings.append({
                "severity": "HIGH",
                "issue": f"{len(dead)} feeds are DEAD (7+ days failing)",
                "detail": "These feeds have been failing for over a week:",
                "samples": [f"{e['url'][:70]} (errors: {e.get('consecutive_errors', 0)}, "
                            f"last ok: {str(e.get('last_success', 'never'))[:10]})"
                            for e in sorted(dead, key=lambda x: -x.get("consecutive_errors", 0))[:10]],
            })
    else:
        stats["health_summary"] = "NO FEED HEALTH DATA (feed_health.json missing)"
        findings.append({
            "severity": "HIGH",
            "issue": "No feed health tracking data",
            "detail": "feed_health.json does not exist on production. Feed failures are invisible. "
                      "The feed_health module is implemented but never initialized its state file.",
        })

    # Dark web feed analysis
    dw_counts = Counter(a.get("source", "") for a in articles if a.get("darkweb"))
    stats["darkweb_sources"] = dict(dw_counts.most_common())

    # ThreatFox IOC batching issue — same title repeated many times
    dw_titles = Counter(a.get("title", "") for a in articles if a.get("darkweb"))
    repeated_dw = [(t, n) for t, n in dw_titles.most_common(10) if n > 5]
    if repeated_dw:
        total_repeated = sum(n for _, n in repeated_dw)
        findings.append({
            "severity": "HIGH",
            "issue": f"Dark web articles with duplicate titles ({total_repeated} articles)",
            "detail": "ThreatFox IOC batches produce identical titles per malware family. "
                      "These should be aggregated (e.g., '10 new IOCs' per run, not separate articles).",
            "samples": [f"'{t[:80]}' x{n}" for t, n in repeated_dw],
        })

    return stats, findings


def print_report(stats, findings):
    sep = "=" * 72
    print(f"\n{sep}")
    print("  FEED HEALTH AUDIT REPORT")
    print(f"  Generated: {datetime.now(timezone.utc).isoformat()[:19]}Z")
    print(sep)

    print(f"\n  Configured feeds: {stats['configured_feeds']}")
    print(f"  Active (producing articles): {stats['active_feeds']}")
    print(f"  Silent (zero articles): {stats['silent_feeds']}")
    print(f"  Activity rate: {stats['active_rate_pct']}%")

    print(f"\n  Health data: {stats.get('health_summary', 'N/A')}")

    if "darkweb_sources" in stats:
        print("\n  Dark web sources:")
        for src, n in stats["darkweb_sources"].items():
            print(f"    {src}: {n}")

    print(f"\n{sep}")
    print(f"  FINDINGS ({len(findings)} total)")
    print(sep)

    for i, f in enumerate(sorted(findings, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[x["severity"]]), 1):
        print(f"\n  [{f['severity']}] #{i}: {f['issue']}")
        print(f"  {f['detail']}")
        if "samples" in f:
            print("  Samples:")
            for s in f["samples"][:10]:
                print(f"    - {s}")
            if len(f["samples"]) > 10:
                print(f"    ... and {len(f['samples']) - 10} more")

    print(f"\n{sep}\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--data", type=str, help="Path to daily_latest.json")
    args = parser.parse_args()

    configured = load_feeds()
    articles = load_articles(args.data)
    health = load_feed_health()

    stats, findings = audit_feeds(configured, articles, health)

    if args.json:
        print(json.dumps({"stats": stats, "findings": findings}, indent=2, default=str))
    else:
        print_report(stats, findings)
