"""Static contract checks for the replacement analyst workspace."""

from pathlib import Path


ROOT = Path(__file__).parent.parent
FRONTEND = ROOT / "frontend" / "src"


def _read(relative_path: str) -> str:
    return (FRONTEND / relative_path).read_text(encoding="utf-8")


def test_primary_navigation_matches_analyst_jobs():
    shell = _read("components/AppShell.tsx")
    for destination in (
        "Overview",
        "News",
        "Vulnerabilities",
        "Campaigns",
        "Watchlists",
        "Briefings",
        "API",
    ):
        assert destination in shell


def test_news_view_handles_pending_summaries_explicitly():
    article_list = _read("components/ArticleList.tsx")
    assert "Summary pending" in article_list
    assert "summary_method" in article_list


def test_vulnerability_view_uses_dedicated_api_filter():
    vulnerabilities = _read("views/VulnerabilitiesView.tsx")
    assert 'view: "vulnerabilities"' in vulnerabilities


def test_design_uses_risk_colors_only_as_semantic_tokens():
    tokens = _read("styles/tokens.css")
    assert "--color-risk-critical" in tokens
    assert "--color-risk-warning" in tokens
    assert "--reading-width" in tokens
