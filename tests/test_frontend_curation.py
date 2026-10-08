"""Static contract checks for the replacement analyst workspace."""

from pathlib import Path


ROOT = Path(__file__).parent.parent
FRONTEND = ROOT / "frontend" / "src"


def _read(relative_path: str) -> str:
    return (FRONTEND / relative_path).read_text(encoding="utf-8")


def test_primary_navigation_matches_analyst_jobs():
    shell = _read("components/AppShell.tsx")
    for destination in (
        "Today",
        "Ledger",
        "Threats",
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
    assert "What changed today" in mission
    assert "api.ledger" in mission


def test_design_uses_risk_colors_only_as_semantic_tokens():
    tokens = _read("styles/tokens.css")
    assert "--color-risk-critical" in tokens
    assert "--color-risk-warning" in tokens
    assert "--reading-width" in tokens


def test_editorial_design_rejects_generic_card_defaults():
    tokens = _read("styles/tokens.css")
    assert "--color-signal: #f2c230" in tokens
    assert "--radius-medium: 0" in tokens
    assert "--shadow-small: none" in tokens
    assert '--font-reading: "Helvetica Neue"' in tokens


def test_shell_uses_a_masthead_instead_of_app_sidebar_and_bottom_tabs():
    shell = _read("components/AppShell.tsx")
    assert 'class="site-masthead"' in shell
    assert "desk-navigation" in shell
    assert 'class="mobile-nav"' not in shell
    assert 'class={`sidebar' not in shell


def test_decision_queue_is_a_ruled_register_not_a_card_stack():
    priority = _read("components/PriorityCard.tsx")
    assert "priority-entry" in priority
    assert "priority-card surface" not in priority
