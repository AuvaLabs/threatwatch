"""Deploy latest threat data to GitHub Pages (docs/ folder).

Copies threatwatch.html → docs/index.html with embedded SSR data
so the site works as a fully static page on GitHub Pages.
"""

import json
import logging
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = BASE_DIR / "docs"
HTML_SRC = BASE_DIR / "threatwatch.html"
FAVICON_SRC = BASE_DIR / "favicon.svg"
DATA_FILE = BASE_DIR / "data" / "output" / "daily_latest.json"
STATS_FILE = BASE_DIR / "data" / "output" / "run_stats.json"
SSR_PLACEHOLDER = "<!-- __SSR_DATA__ -->"


def load_json(path):
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def build_ssr_html():
    """Build static HTML with embedded article data."""
    html = HTML_SRC.read_text()

    articles = load_json(DATA_FILE) or []
    stats = load_json(STATS_FILE)

    ssr_payload = {"articles": articles}
    if stats:
        ssr_payload["stats"] = stats

    raw_json = json.dumps(ssr_payload, separators=(",", ":"))
    safe_json = raw_json.replace("</", "<\\/")
    ssr_script = f'<script id="ssr-data" type="application/json">{safe_json}</script>'

    html = html.replace(SSR_PLACEHOLDER, ssr_script)

    # For GitHub Pages, the API fetch will fail (no server), so disable
    # the periodic refresh to avoid console errors. SSR data is sufficient.
    html = html.replace(
        "setInterval(refreshData, REFRESH_INTERVAL);",
        "// setInterval(refreshData, REFRESH_INTERVAL); // Disabled for static site",
    )

    return html


def deploy():
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    DOCS_DIR.mkdir(exist_ok=True)

    # Build and write static HTML
    html = build_ssr_html()
    index_path = DOCS_DIR / "index.html"
    index_path.write_text(html)
    logging.info(f"Built {index_path} ({len(html):,} bytes)")

    # Copy favicon
    if FAVICON_SRC.exists():
        shutil.copy2(FAVICON_SRC, DOCS_DIR / "favicon.svg")

    # Also provide articles.json as a static data file
    articles = load_json(DATA_FILE) or []
    data_path = DOCS_DIR / "articles.json"
    data_path.write_text(json.dumps(articles, separators=(",", ":")))
    logging.info(f"Wrote {data_path} ({len(articles)} articles)")

    # Write RSS feed if available
    rss_src = BASE_DIR / "data" / "output" / "rss_cyberattacks.xml"
    if rss_src.exists():
        shutil.copy2(rss_src, DOCS_DIR / "feed.xml")
        logging.info("Copied RSS feed to docs/feed.xml")

    # Git operations
    try:
        subprocess.run(["git", "add", "docs/"], cwd=BASE_DIR, check=True)

        # Check if there are changes to commit
        result = subprocess.run(
            ["git", "diff", "--cached", "--quiet", "docs/"],
            cwd=BASE_DIR,
            capture_output=True,
        )
        if result.returncode == 0:
            logging.info("No changes to deploy.")
            return

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        msg = f"data: update threat intel feed — {now}"
        subprocess.run(
            ["git", "commit", "-m", msg, "--", "docs/"],
            cwd=BASE_DIR,
            check=True,
        )
        subprocess.run(
            ["git", "push", "origin", "main"],
            cwd=BASE_DIR,
            check=True,
        )
        logging.info(f"Deployed to GitHub Pages at {now}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Git operation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    deploy()
