"""ThreatWatch Quality Audit Script.

Analyzes daily_latest.json for data accuracy, coverage, and quality issues.
Produces a structured report with actionable findings.

Usage:
    python scripts/audit_quality.py [--json] [--data PATH]
"""

import json
import re
import sys
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.config import CATEGORIES, FEED_CUTOFF_DAYS
from modules.keyword_classifier import _RULES, _NOISE_PATTERNS, _CYBER_KEYWORDS


def load_articles(path=None):
    if path is None:
        path = Path(__file__).parent.parent / "data" / "output" / "daily_latest.json"
    return json.loads(Path(path).read_text(encoding="utf-8"))


def audit_classification(articles):
    """Audit classification accuracy and coverage."""
    findings = []
    stats = {}

    # Category distribution
    cat_counts = Counter(a.get("category", "MISSING") for a in articles)
    stats["category_distribution"] = dict(cat_counts.most_common())

    # Confidence distribution
    conf_counts = Counter(a.get("confidence", 0) for a in articles)
    stats["confidence_distribution"] = dict(sorted(conf_counts.items()))

    # Unclassified rate (General Cyber Threat at confidence=60 is the fallback)
    fallback = [a for a in articles if a.get("category") == "General Cyber Threat"
                and a.get("confidence", 0) == 60]
    stats["unclassified_count"] = len(fallback)
    stats["unclassified_pct"] = round(len(fallback) / len(articles) * 100, 1) if articles else 0

    if stats["unclassified_pct"] > 15:
        findings.append({
            "severity": "HIGH",
            "issue": "High unclassified rate",
            "detail": f"{stats['unclassified_count']} articles ({stats['unclassified_pct']}%) "
                      f"fell to 'General Cyber Threat' fallback. Many are classifiable.",
            "samples": [a["title"][:120] for a in random.sample(fallback, min(10, len(fallback)))],
        })

    # Categories not in official list
    unknown_cats = [c for c in cat_counts if c not in CATEGORIES and c != "MISSING"]
    if unknown_cats:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Unknown categories found",
            "detail": f"Categories not in official list: {unknown_cats}",
            "samples": [a["title"][:120] for a in articles if a.get("category") in unknown_cats],
        })

    # Noise that slipped through — check General Cyber Threat articles against patterns
    noise_leaked = []
    for a in fallback:
        title = a.get("title", "")
        # Check for common noise patterns the classifier should have caught
        if any(p.search(title) for p in [
            re.compile(r"(award|badge|report|leader)\b.*\b(G2|Gartner|Forrester)", re.I),
            re.compile(r"\b(tips?|ways?|steps?|practices?)\s+(to|for)\s+(protect|secure|stay)", re.I),
            re.compile(r"\b(training|course|bootcamp|certification|career)\b", re.I),
            re.compile(r"\b(launches?|unveils?|introduces?|announces?)\b.*\b(product|platform|solution)\b", re.I),
            re.compile(r"\b(raises?|secures?|closes?)\s+\$\d", re.I),
        ]):
            noise_leaked.append(a)

    if noise_leaked:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Noise articles passed through filters",
            "detail": f"{len(noise_leaked)} articles appear to be noise (awards, training, tips, product launches) "
                      f"that bypassed the noise filter.",
            "samples": [a["title"][:120] for a in noise_leaked[:10]],
        })

    # Misclassification candidates — articles where title strongly suggests different category
    misclass_checks = [
        ("Ransomware", re.compile(r"ransomware|ransom\s+demand|lockbit|blackcat|cl0p|akira", re.I)),
        ("Data Breach", re.compile(r"data\s+breach|breached|data\s+leak|records\s+stolen", re.I)),
        ("Nation-State Attack", re.compile(r"\bapt\d{1,3}\b|nation.state|state.sponsored|lazarus|typhoon", re.I)),
        ("Zero-Day Exploit", re.compile(r"zero.day|0day|actively\s+exploited", re.I)),
        ("Phishing", re.compile(r"phishing|spearphish|credential\s+harvest|BEC", re.I)),
    ]
    misclassified = []
    for a in articles:
        title = a.get("title", "")
        assigned = a.get("category", "")
        for expected_cat, pattern in misclass_checks:
            if pattern.search(title) and assigned != expected_cat and assigned != "General Cyber Threat":
                misclassified.append({
                    "title": title[:120],
                    "assigned": assigned,
                    "expected": expected_cat,
                })
                break

    if misclassified:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Potential misclassifications",
            "detail": f"{len(misclassified)} articles may be misclassified (first-match-wins rule order issue).",
            "samples": [f"[{m['assigned']} -> {m['expected']}] {m['title']}" for m in misclassified[:10]],
        })

    # French/non-English articles not getting classified properly
    non_english = [a for a in fallback if any(c in a.get("title", "") for c in "àéèêëîïôùûüç")]
    if non_english:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Non-English articles falling to fallback",
            "detail": f"{len(non_english)} non-English articles (likely French) landed in General Cyber Threat. "
                      f"Regex rules are English-only.",
            "samples": [a["title"][:120] for a in non_english[:8]],
        })

    stats["noise_leaked_count"] = len(noise_leaked)
    stats["misclassified_count"] = len(misclassified)
    stats["non_english_fallback"] = len(non_english)

    return stats, findings


def audit_timeliness(articles):
    """Audit article freshness and date handling."""
    findings = []
    stats = {}

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=FEED_CUTOFF_DAYS)

    old_articles = []
    unparseable_dates = []
    no_date = []

    for a in articles:
        pub = a.get("published", "")
        if not pub:
            no_date.append(a)
            continue

        try:
            # Try ISO format (contains "T" separator but not in day names like "Tue")
            if "T" in pub and pub[:4].isdigit():
                dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
            else:
                # Try bare datetime formats (e.g., "2026-03-14 20:52:27")
                dt = None
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d"):
                    try:
                        dt = datetime.strptime(pub[:len(fmt) + 10], fmt)
                        break
                    except (ValueError, TypeError):
                        continue
                if dt is None:
                    # Try RFC 2822 — strip non-standard tz abbreviations first
                    from email.utils import parsedate_to_datetime
                    import re as _re
                    cleaned = _re.sub(
                        r"\s+(CEST|CET|IST|BST|PDT|PST|CDT|CST|MDT|MST|EDT|EST|JST|KST|AEST|AEDT|NZST|NZDT)$",
                        " +0000", pub.strip(),
                    )
                    dt = parsedate_to_datetime(cleaned)

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            age_days = (now - dt).total_seconds() / 86400
            if age_days > FEED_CUTOFF_DAYS + 1:  # 1 day grace
                old_articles.append({"title": a["title"][:100], "date": pub[:20], "age_days": round(age_days)})
        except Exception:
            unparseable_dates.append({"title": a.get("title", "")[:100], "date": pub[:30]})

    stats["total_articles"] = len(articles)
    stats["old_articles_count"] = len(old_articles)
    stats["old_articles_pct"] = round(len(old_articles) / len(articles) * 100, 1) if articles else 0
    stats["unparseable_dates"] = len(unparseable_dates)
    stats["no_date_articles"] = len(no_date)

    if old_articles:
        # Group by age bucket
        buckets = defaultdict(int)
        for a in old_articles:
            days = a["age_days"]
            if days > 365:
                buckets["1+ years old"] += 1
            elif days > 30:
                buckets["1-12 months old"] += 1
            else:
                buckets["8-30 days old"] += 1

        findings.append({
            "severity": "HIGH",
            "issue": "Articles past cutoff date in feed",
            "detail": f"{len(old_articles)} articles ({stats['old_articles_pct']}%) are older than "
                      f"{FEED_CUTOFF_DAYS}-day cutoff. Age breakdown: {dict(buckets)}",
            "samples": sorted(old_articles, key=lambda x: -x["age_days"])[:10],
        })

    if unparseable_dates:
        findings.append({
            "severity": "LOW",
            "issue": "Unparseable date formats",
            "detail": f"{len(unparseable_dates)} articles have dates that couldn't be parsed.",
            "samples": unparseable_dates[:5],
        })

    return stats, findings


def audit_regions(articles):
    """Audit region accuracy."""
    findings = []
    stats = {}

    region_counts = Counter(a.get("feed_region", "MISSING") for a in articles)
    stats["region_distribution"] = dict(region_counts.most_common(20))

    # Multi-region strings (more than 3 regions = collapsed to Global, but some slip through)
    multi_region = [r for r in region_counts if "," in r and r.count(",") >= 3]
    multi_count = sum(region_counts[r] for r in multi_region)
    stats["multi_region_articles"] = multi_count
    stats["distinct_multi_regions"] = len(multi_region)

    if multi_region:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Excessive multi-region tagging",
            "detail": f"{multi_count} articles have 4+ region tags instead of being collapsed to Global. "
                      f"{len(multi_region)} distinct multi-region strings.",
            "samples": [(r, region_counts[r]) for r in sorted(multi_region, key=lambda x: -region_counts[x])[:8]],
        })

    # Region accuracy spot-check: look for clear mismatches in title vs region
    mismatches = []
    region_keywords = {
        "US": [r"\b(US|U\.S\.|American|United States|Washington DC|Pentagon|FBI|CISA|NSA)\b"],
        "Europe": [r"\b(UK|Britain|British|France|French|Germany|German|EU|European)\b"],
        "APAC": [r"\b(Japan|Japanese|China|Chinese|India|Indian|Australia|Australian|South Korea|Korean)\b"],
        "Middle East": [r"\b(Israel|Israeli|Iran|Iranian|Saudi|UAE|Emirati)\b"],
    }
    for a in articles:
        title = a.get("title", "")
        assigned = a.get("feed_region", "Global")
        if assigned == "Global" or "," in assigned:
            continue
        for expected_region, patterns in region_keywords.items():
            for p in patterns:
                if re.search(p, title, re.I) and assigned != expected_region:
                    # Only flag clear mismatches
                    if not any(re.search(kp, title, re.I) for kps in region_keywords.values()
                              if kps != patterns for kp in kps):
                        mismatches.append({
                            "title": title[:100],
                            "assigned": assigned,
                            "expected": expected_region,
                        })
                    break

    stats["region_mismatches"] = len(mismatches)
    if mismatches:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Region mismatch in title vs assigned region",
            "detail": f"{len(mismatches)} articles have title mentioning one region but assigned to another.",
            "samples": [f"[{m['assigned']} -> {m['expected']}] {m['title']}" for m in mismatches[:8]],
        })

    return stats, findings


def audit_sources(articles):
    """Audit source distribution and quality."""
    findings = []
    stats = {}

    source_counts = Counter(a.get("source", "MISSING") for a in articles)
    stats["total_sources"] = len(source_counts)
    stats["top_sources"] = dict(source_counts.most_common(15))

    # Check for disproportionate sources (>10% of total)
    total = len(articles)
    dominant = [(s, n) for s, n in source_counts.items()
                if n > total * 0.08 and s not in ("darkweb:threatfox", "darkweb:ransomware.live")]
    if dominant:
        findings.append({
            "severity": "HIGH",
            "issue": "Disproportionate source volume",
            "detail": f"Sources with >8% of all articles: {[(s[:60], n, f'{n/total*100:.1f}%') for s, n in dominant]}. "
                      f"Check if these feeds are returning historic content.",
        })

    # Check for feeds in config but not in data (coverage gaps)
    # We'd need to load config for this — done in feed health audit

    # Dark web vs normal ratio
    dw_count = sum(1 for a in articles if a.get("darkweb"))
    stats["darkweb_count"] = dw_count
    stats["darkweb_pct"] = round(dw_count / total * 100, 1) if total else 0
    stats["normal_count"] = total - dw_count

    return stats, findings


def audit_dedup(articles):
    """Audit deduplication effectiveness."""
    findings = []
    stats = {}

    # Check for near-duplicate titles still in the output
    from modules.deduplicator import normalize_title, _make_word_shingles, _word_overlap_ratio

    titles = [(i, normalize_title(a["title"]), a["title"]) for i, a in enumerate(articles)]
    near_dupes = []

    # Sample-based check (full O(n^2) is too slow for 4k articles)
    random.seed(42)
    sample_indices = set(random.sample(range(len(titles)), min(500, len(titles))))

    for i in sample_indices:
        _, norm_i, raw_i = titles[i]
        shingles_i = _make_word_shingles(norm_i)
        if len(shingles_i) < 3:
            continue
        for j in range(i + 1, len(titles)):
            _, norm_j, raw_j = titles[j]
            shingles_j = _make_word_shingles(norm_j)
            if len(shingles_j) < 3:
                continue
            sim = _word_overlap_ratio(shingles_i, shingles_j)
            if 0.45 <= sim < 0.6:  # Just below threshold — potential misses
                near_dupes.append({
                    "similarity": round(sim, 3),
                    "title_a": raw_i[:100],
                    "title_b": raw_j[:100],
                })

    stats["near_duplicate_pairs"] = len(near_dupes)
    stats["articles_with_related"] = sum(1 for a in articles if a.get("related_articles"))
    stats["total_related_merged"] = sum(len(a.get("related_articles", [])) for a in articles)

    if near_dupes:
        findings.append({
            "severity": "LOW",
            "issue": "Near-duplicate articles below threshold",
            "detail": f"{len(near_dupes)} article pairs have similarity 0.45-0.59 (just below 0.6 threshold). "
                      f"Some may be true duplicates the fuzzy dedup missed.",
            "samples": sorted(near_dupes, key=lambda x: -x["similarity"])[:8],
        })

    # Check for exact title duplicates (should never happen)
    title_set = Counter(a["title"] for a in articles)
    exact_dupes = [(t, n) for t, n in title_set.items() if n > 1]
    stats["exact_title_duplicates"] = len(exact_dupes)

    if exact_dupes:
        findings.append({
            "severity": "HIGH",
            "issue": "Exact title duplicates in output",
            "detail": f"{len(exact_dupes)} titles appear more than once — dedup should have caught these.",
            "samples": [(t[:100], n) for t, n in sorted(exact_dupes, key=lambda x: -x[1])[:8]],
        })

    return stats, findings


def audit_data_quality(articles):
    """Audit general data quality — missing fields, broken data."""
    findings = []
    stats = {}

    required_fields = ["title", "link", "category", "confidence", "published", "source"]
    field_missing = defaultdict(int)

    for a in articles:
        for f in required_fields:
            if not a.get(f):
                field_missing[f] += 1

    stats["field_completeness"] = {
        f: round((1 - field_missing[f] / len(articles)) * 100, 1) for f in required_fields
    }

    incomplete = {f: n for f, n in field_missing.items() if n > 0}
    if incomplete:
        findings.append({
            "severity": "MEDIUM" if any(n > len(articles) * 0.05 for n in incomplete.values()) else "LOW",
            "issue": "Missing required fields",
            "detail": f"Field completeness issues: {incomplete}",
        })

    # Check for empty/meaningless summaries
    no_summary = sum(1 for a in articles if not a.get("summary"))
    stats["no_summary_count"] = no_summary
    stats["no_summary_pct"] = round(no_summary / len(articles) * 100, 1) if articles else 0

    return stats, findings


def generate_report(articles, output_json=False):
    """Run all audits and produce a consolidated report."""
    random.seed(42)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_articles": len(articles),
        "audits": {},
        "findings": [],
        "quality_score": 0,
    }

    auditors = [
        ("classification", audit_classification),
        ("timeliness", audit_timeliness),
        ("regions", audit_regions),
        ("sources", audit_sources),
        ("deduplication", audit_dedup),
        ("data_quality", audit_data_quality),
    ]

    all_findings = []
    for name, fn in auditors:
        stats, findings = fn(articles)
        report["audits"][name] = stats
        all_findings.extend(findings)

    report["findings"] = sorted(all_findings, key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[f["severity"]])

    # Quality score (100 = perfect, deductions for issues)
    score = 100
    for f in all_findings:
        if f["severity"] == "HIGH":
            score -= 15
        elif f["severity"] == "MEDIUM":
            score -= 5
        elif f["severity"] == "LOW":
            score -= 2
    report["quality_score"] = max(0, score)

    if output_json:
        return report

    # Human-readable output
    sep = "=" * 72
    print(f"\n{sep}")
    print(f"  THREATWATCH QUALITY AUDIT REPORT")
    print(f"  Generated: {report['generated_at'][:19]}Z")
    print(f"  Articles analyzed: {report['total_articles']}")
    print(f"  Quality Score: {report['quality_score']}/100")
    print(sep)

    for name, stats in report["audits"].items():
        print(f"\n{'─' * 40}")
        print(f"  {name.upper()}")
        print(f"{'─' * 40}")
        for k, v in stats.items():
            if isinstance(v, dict) and len(v) > 5:
                print(f"  {k}:")
                for kk, vv in list(v.items())[:15]:
                    print(f"    {kk}: {vv}")
                if len(v) > 15:
                    print(f"    ... and {len(v) - 15} more")
            else:
                print(f"  {k}: {v}")

    print(f"\n{sep}")
    print(f"  FINDINGS ({len(all_findings)} total)")
    print(sep)

    for i, f in enumerate(report["findings"], 1):
        print(f"\n  [{f['severity']}] #{i}: {f['issue']}")
        print(f"  {f['detail']}")
        if "samples" in f:
            print(f"  Samples:")
            for s in f["samples"][:5]:
                print(f"    - {s}")
            if len(f["samples"]) > 5:
                print(f"    ... and {len(f['samples']) - 5} more")

    print(f"\n{sep}")
    print(f"  QUALITY SCORE: {report['quality_score']}/100")
    print(sep)
    print()

    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ThreatWatch Quality Audit")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--data", type=str, help="Path to daily_latest.json")
    args = parser.parse_args()

    articles = load_articles(args.data)
    report = generate_report(articles, output_json=args.json)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
