import json
import logging
import sys
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.config import OUTPUT_DIR

DAILY_DIR = OUTPUT_DIR / "daily"
WEEKLY_DIR = OUTPUT_DIR / "weekly"
DIGEST_DIR = OUTPUT_DIR / "digests"

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")


def load_week_articles(target_date=None):
    if target_date is None:
        target_date = datetime.now(timezone.utc).date()

    week_start = target_date - timedelta(days=target_date.weekday())
    week_end = week_start + timedelta(days=6)

    articles = []
    seen_hashes = set()

    for day_offset in range(7):
        date = week_start + timedelta(days=day_offset)
        daily_file = DAILY_DIR / f"{date.isoformat()}.json"
        if not daily_file.exists():
            continue
        try:
            with open(daily_file, "r", encoding="utf-8") as f:
                day_articles = json.load(f)
                for article in day_articles:
                    h = article.get("hash", article.get("link"))
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        articles.append(article)
        except (json.JSONDecodeError, IOError) as e:
            logging.warning(f"Failed to load {daily_file}: {e}")

    return articles, week_start, week_end


def generate_digest(articles, week_start, week_end):
    category_counts = Counter(a.get("category", "Unknown") for a in articles)
    confidence_avg = (
        sum(a.get("confidence", 0) for a in articles) / len(articles)
        if articles
        else 0
    )

    top_categories = category_counts.most_common(5)
    high_confidence = [a for a in articles if a.get("confidence", 0) >= 80]
    high_confidence.sort(key=lambda a: a.get("confidence", 0), reverse=True)

    sources = Counter(a.get("source", "unknown") for a in articles)

    return {
        "week_start": week_start.isoformat(),
        "week_end": week_end.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_articles": len(articles),
        "average_confidence": round(confidence_avg, 1),
        "top_categories": [
            {"category": cat, "count": count} for cat, count in top_categories
        ],
        "top_sources": [
            {"source": src, "count": count}
            for src, count in sources.most_common(10)
        ],
        "top_incidents": [
            {
                "title": a.get("translated_title", a.get("title", "")),
                "link": a.get("link", ""),
                "category": a.get("category", ""),
                "confidence": a.get("confidence", 0),
                "summary": a.get("summary", ""),
                "published": a.get("published", ""),
            }
            for a in high_confidence[:20]
        ],
    }


def write_digest_json(digest, week_start):
    WEEKLY_DIR.mkdir(parents=True, exist_ok=True)
    week_slug = week_start.strftime("%Y-W%U")
    json_path = WEEKLY_DIR / f"{week_slug}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(digest, f, indent=2, ensure_ascii=False)
    logging.info(f"Weekly JSON saved to {json_path}")


def write_digest_markdown(digest, week_start):
    DIGEST_DIR.mkdir(parents=True, exist_ok=True)
    week_slug = week_start.strftime("%Y-W%U")
    md_path = DIGEST_DIR / f"digest-{week_slug}.md"

    lines = [
        "# ThreatDigest Weekly Report",
        f"**Week of {digest['week_start']} to {digest['week_end']}**\n",
        f"Generated: {digest['generated_at']} UTC\n",
        "---\n",
        "## Summary\n",
        f"- **Total incidents tracked:** {digest['total_articles']}",
        f"- **Average confidence:** {digest['average_confidence']}%\n",
        "## Top Threat Categories\n",
        "| Category | Count |",
        "|----------|-------|",
    ]

    for cat in digest["top_categories"]:
        lines.append(f"| {cat['category']} | {cat['count']} |")

    lines.extend([
        "\n## Top Sources\n",
        "| Source | Articles |",
        "|--------|----------|",
    ])
    for src in digest["top_sources"]:
        lines.append(f"| {src['source'][:60]} | {src['count']} |")

    lines.extend(["\n## Top Incidents\n"])

    for i, incident in enumerate(digest["top_incidents"][:10], 1):
        lines.append(f"### {i}. {incident['title']}")
        lines.append(f"- **Category:** {incident['category']}")
        lines.append(f"- **Confidence:** {incident['confidence']}%")
        lines.append(f"- **Link:** {incident['link']}")
        if incident["summary"]:
            lines.append(f"- **Summary:** {incident['summary']}")
        lines.append("")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    logging.info(f"Weekly digest markdown saved to {md_path}")


def main():
    articles, week_start, week_end = load_week_articles()

    if not articles:
        logging.warning("No articles found for this week.")
        return

    digest = generate_digest(articles, week_start, week_end)
    write_digest_json(digest, week_start)
    write_digest_markdown(digest, week_start)

    logging.info(
        f"Weekly digest complete: {digest['total_articles']} articles, "
        f"top category: {digest['top_categories'][0]['category'] if digest['top_categories'] else 'N/A'}"
    )


if __name__ == "__main__":
    main()
