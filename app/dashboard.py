import json
import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
OUTPUT_DIR = BASE_DIR / "data" / "output"
STATS_FILE = OUTPUT_DIR / "stats.json"
DAILY_DIR = OUTPUT_DIR / "daily"
HOURLY_LATEST = OUTPUT_DIR / "hourly_latest.json"
DAILY_LATEST = OUTPUT_DIR / "daily_latest.json"


def load_json_safe(path):
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def load_stats():
    if not STATS_FILE.exists():
        return {}
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def generate_dashboard_html():
    articles = load_json_safe(DAILY_LATEST)
    articles.sort(key=lambda a: _parse_pub_date(a.get("published", "")), reverse=True)
    stats = load_stats()
    latest_run = stats.get("latest", {})
    total_reviewed = sum(r.get("news_reviewed", 0) for r in stats.get("runs", []))
    threat_level, threat_class = _assess_threat_level(articles)

    categories = {}
    for a in articles:
        cat = a.get("category", "Unknown")
        categories[cat] = categories.get(cat, 0) + 1

    sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatDigest Hub</title>
<style>
:root {{
    --bg: #ffffff;
    --surface: #f8f9fa;
    --border: #e2e6ea;
    --border-light: #f0f1f3;
    --text: #1a1a2e;
    --text-secondary: #495057;
    --text-muted: #868e96;
    --accent: #2563eb;
    --accent-light: #eff6ff;
    --danger: #dc2626;
    --danger-light: #fef2f2;
    --warning: #d97706;
    --warning-light: #fffbeb;
    --success: #059669;
    --success-light: #ecfdf5;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
}}
.container {{ max-width: 1120px; margin: 0 auto; padding: 32px 24px; }}
header {{
    padding: 0 0 28px;
    margin-bottom: 32px;
    border-bottom: 1px solid var(--border);
}}
header h1 {{
    font-size: 22px;
    font-weight: 700;
    color: var(--text);
    letter-spacing: -0.3px;
}}
header .subtitle {{
    color: var(--text-muted);
    font-size: 13px;
    margin-top: 6px;
    font-weight: 400;
}}

.stats-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 36px;
}}
@media (max-width: 768px) {{
    .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
}}
.stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
}}
.stat-card .label {{
    color: var(--text-muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    font-weight: 600;
}}
.stat-card .value {{
    font-size: 32px;
    font-weight: 700;
    margin-top: 6px;
    letter-spacing: -0.5px;
}}
.stat-card .value.accent {{ color: var(--accent); }}
.stat-card .value.warning {{ color: var(--warning); }}
.stat-card .value.success {{ color: var(--success); }}
.stat-card .value.danger {{ color: var(--danger); }}

.section {{ margin-bottom: 36px; }}
.section h2 {{
    font-size: 15px;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 14px;
    letter-spacing: -0.1px;
}}

.categories {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 24px;
}}
.cat-badge {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
    cursor: pointer;
    transition: all 0.15s ease;
    user-select: none;
}}
.cat-badge:hover {{
    border-color: var(--accent);
    color: var(--accent);
    background: var(--accent-light);
}}
.cat-badge.active {{
    border-color: var(--accent);
    color: var(--accent);
    background: var(--accent-light);
    font-weight: 600;
}}
.cat-badge .count {{
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    margin-left: 4px;
}}
.cat-badge.active .count {{ color: var(--accent); }}

.search-bar {{
    width: 100%;
    padding: 10px 14px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-size: 14px;
    margin-bottom: 16px;
    outline: none;
    transition: border-color 0.15s ease;
}}
.search-bar::placeholder {{ color: var(--text-muted); }}
.search-bar:focus {{ border-color: var(--accent); box-shadow: 0 0 0 3px rgba(37,99,235,0.08); }}

table {{
    width: 100%;
    border-collapse: collapse;
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
}}
thead {{ background: var(--surface); }}
th {{
    padding: 10px 16px;
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 600;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
}}
td {{
    padding: 14px 16px;
    font-size: 14px;
    border-bottom: 1px solid var(--border-light);
    vertical-align: top;
}}
tr:last-child td {{ border-bottom: none; }}
tr:hover {{ background: var(--surface); }}
td a {{
    color: var(--text);
    text-decoration: none;
    font-weight: 500;
}}
td a:hover {{ color: var(--accent); }}

.summary-text {{
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 4px;
    line-height: 1.4;
}}
.related-tag {{
    display: inline-block;
    font-size: 11px;
    color: var(--accent);
    background: var(--accent-light);
    padding: 1px 8px;
    border-radius: 4px;
    margin-top: 6px;
    font-weight: 500;
}}

.confidence {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
}}
.conf-high {{ background: var(--success-light); color: var(--success); }}
.conf-med {{ background: var(--warning-light); color: var(--warning); }}
.conf-low {{ background: var(--danger-light); color: var(--danger); }}

.source-name {{
    font-size: 13px;
    color: var(--text-secondary);
}}
.pub-date {{
    font-size: 13px;
    color: var(--text-muted);
    white-space: nowrap;
}}

.empty-state {{
    text-align: center;
    padding: 60px 20px;
    color: var(--text-muted);
}}
.empty-state h3 {{
    font-size: 16px;
    font-weight: 600;
    color: var(--text-secondary);
    margin-bottom: 8px;
}}
.empty-state p {{ font-size: 14px; }}

footer {{
    border-top: 1px solid var(--border);
    padding: 24px 0 0;
    margin-top: 48px;
    color: var(--text-muted);
    font-size: 12px;
    text-align: center;
}}
</style>
</head>
<body>
<div class="container">
<header>
    <h1>ThreatDigest Hub</h1>
    <div class="subtitle">Cybersecurity threat intelligence - Last updated: {now}</div>
</header>

<div class="stats-grid">
    <div class="stat-card">
        <div class="label">Articles Today</div>
        <div class="value accent">{len(articles)}</div>
    </div>
    <div class="stat-card">
        <div class="label">Feeds Monitored</div>
        <div class="value">{latest_run.get('feeds_loaded', 'N/A')}</div>
    </div>
    <div class="stat-card">
        <div class="label">News Reviewed</div>
        <div class="value warning">{total_reviewed:,}</div>
    </div>
    <div class="stat-card">
        <div class="label">Cyber News Level</div>
        <div class="value {threat_class}">{threat_level}</div>
    </div>
</div>

<div class="section">
    <h2>Categories</h2>
    <div class="categories">
        <span class="cat-badge active" onclick="filterCategory('all')">All <span class="count">{len(articles)}</span></span>
"""

    for cat, count in sorted_cats:
        html += f'        <span class="cat-badge" onclick="filterCategory(\'{cat}\')">{cat} <span class="count">{count}</span></span>\n'

    html += """    </div>
</div>

<div class="section">
    <h2>Threat Feed</h2>
    <input type="text" class="search-bar" placeholder="Search articles..." oninput="searchArticles(this.value)">
"""

    if not articles:
        html += """    <div class="empty-state">
        <h3>No articles yet</h3>
        <p>The pipeline hasn't run yet. Articles will appear here after the first run.</p>
    </div>
"""
    else:
        html += """    <table>
        <thead>
            <tr>
                <th style="width:50%">Title</th>
                <th>Category</th>
                <th>Confidence</th>
                <th>Published</th>
            </tr>
        </thead>
        <tbody id="articles-body">
"""

        for a in articles:
            title = a.get("translated_title", a.get("title", "No Title"))
            link = a.get("link", "#")
            category = a.get("category", "Unknown")
            confidence = a.get("confidence", 0)
            published = _format_pub_date(a.get("published", ""))
            summary = a.get("summary", "")
            related = a.get("related_articles", [])

            conf_class = "conf-high" if confidence >= 80 else ("conf-med" if confidence >= 50 else "conf-low")

            title_escaped = title.replace('"', '&quot;').replace("'", "&#39;").replace("<", "&lt;").replace(">", "&gt;")
            summary_escaped = summary.replace('"', '&quot;').replace("'", "&#39;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")
            title_display = title.replace("<", "&lt;").replace(">", "&gt;")

            html += f'            <tr data-category="{category}" data-title="{title_escaped.lower()}">\n'
            html += f'                <td><a href="{link}" target="_blank" rel="noopener">{title_display}</a>'
            if summary:
                html += f'<div class="summary-text">{summary_escaped[:140]}</div>'
            if related:
                html += f'<span class="related-tag">+{len(related)} source{"s" if len(related) > 1 else ""}</span>'
            html += '</td>\n'
            html += f'                <td>{category}</td>\n'
            html += f'                <td><span class="confidence {conf_class}">{confidence}%</span></td>\n'
            html += f'                <td><span class="pub-date">{published}</span></td>\n'
            html += '            </tr>\n'

        html += """        </tbody>
    </table>
"""

    html += """</div>

<footer>
    ThreatDigest Hub by CyberOneHQ
</footer>
</div>

<script>
function filterCategory(cat) {
    document.querySelectorAll('.cat-badge').forEach(b => b.classList.remove('active'));
    event.target.closest('.cat-badge').classList.add('active');
    document.querySelectorAll('#articles-body tr').forEach(row => {
        row.style.display = (cat === 'all' || row.dataset.category === cat) ? '' : 'none';
    });
}

function searchArticles(query) {
    const q = query.toLowerCase();
    document.querySelectorAll('#articles-body tr').forEach(row => {
        row.style.display = row.dataset.title.includes(q) ? '' : 'none';
    });
}
</script>
</body>
</html>"""
    return html


def _parse_pub_date(pub_str):
    if not pub_str:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return parsedate_to_datetime(pub_str)
    except (ValueError, TypeError):
        pass
    try:
        dt = datetime.fromisoformat(pub_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d"):
        try:
            return datetime.strptime(pub_str, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return datetime.min.replace(tzinfo=timezone.utc)


def _format_pub_date(pub_str):
    if not pub_str:
        return "N/A"
    dt = _parse_pub_date(pub_str)
    if dt == datetime.min.replace(tzinfo=timezone.utc):
        return pub_str[:16] if pub_str else "N/A"
    return dt.strftime("%Y-%m-%d %H:%M")


CRITICAL_CATEGORIES = {"Zero-Day Exploit", "Nation-State Attack", "Supply Chain Attack", "Cyber Espionage"}
HIGH_CATEGORIES = {"Ransomware", "Data Breach", "Insider Threat", "Account Takeover"}


def _assess_threat_level(articles):
    if not articles:
        return "MEDIUM", "warning"

    critical_count = sum(
        1 for a in articles
        if a.get("category") in CRITICAL_CATEGORIES and a.get("confidence", 0) >= 80
    )
    high_count = sum(
        1 for a in articles
        if a.get("category") in HIGH_CATEGORIES and a.get("confidence", 0) >= 70
    )

    if critical_count >= 5:
        return "CRITICAL", "danger"
    if critical_count >= 2 or high_count >= 10:
        return "HIGH", "warning"
    return "MEDIUM", "success"


def _cache_rate(run):
    hits = run.get("cache_hits", 0)
    misses = run.get("cache_misses", 0)
    total = hits + misses
    if total == 0:
        return "N/A"
    return f"{round(hits / total * 100)}%"


def _extract_source_name(url):
    if not url:
        return "Unknown"
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or ""
        hostname = hostname.replace("www.", "").replace("feeds.", "")
        parts = hostname.split(".")
        return parts[0].capitalize() if parts else "Unknown"
    except Exception:
        return "Unknown"


def build_dashboard():
    html = generate_dashboard_html()
    output_path = OUTPUT_DIR / "dashboard.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logging.info(f"Dashboard generated at {output_path}")

    docs_path = BASE_DIR / "docs" / "index.html"
    docs_path.parent.mkdir(parents=True, exist_ok=True)
    with open(docs_path, "w", encoding="utf-8") as f:
        f.write(html)
    logging.info(f"Dashboard also deployed to {docs_path}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    build_dashboard()
