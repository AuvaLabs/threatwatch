"""Static contract checks for the replacement analyst workspace."""

from pathlib import Path


ROOT = Path(__file__).parent.parent
FRONTEND = ROOT / "frontend" / "src"


def _read(relative_path: str) -> str:
    return (FRONTEND / relative_path).read_text(encoding="utf-8")


def test_primary_navigation_matches_analyst_jobs():
    shell = _read("components/AppShell.tsx")
    for destination in (
        "Mission Control",
        "Threats",
        "Exposure",
        "Investigations",
        "Hunts",
        "Reports",
        "Automation",
        "Sources",
    ):
        assert destination in shell


def test_source_library_handles_pending_summaries_explicitly():
    article_list = _read("components/ArticleList.tsx")
    assert "Summary pending" in article_list
    assert "summary_method" in article_list


def test_mission_control_uses_operational_decision_api():
    mission = _read("views/MissionControlView.tsx")
    assert "api.operations" in mission
    assert "Decision queue" in mission


def test_design_uses_risk_colors_only_as_semantic_tokens():
    tokens = _read("styles/tokens.css")
    assert "--color-risk-critical" in tokens
    assert "--color-risk-warning" in tokens
    assert "--reading-width" in tokens
