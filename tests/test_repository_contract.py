from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_ci_enforces_complete_quality_harness():
    workflow = _read(".github/workflows/ci.yml")

    required_steps = (
        "permissions:\n  contents: read",
        "--cov-fail-under=80",
        "actions/setup-node@",
        "npm ci",
        "npm test",
        "npm run build",
        "npm audit --audit-level=high",
    )

    for step in required_steps:
        assert step in workflow


def test_generated_public_payloads_are_ignored():
    ignore_rules = _read(".gitignore").splitlines()

    assert "docs/index.html" in ignore_rules
    assert "docs/articles.json" in ignore_rules


def test_public_contributor_docs_match_current_architecture():
    contributing = _read("CONTRIBUTING.md")
    readme = _read("README.md")
    security = _read("SECURITY.md")

    stale_claims = (
        "MIT License",
        "threatwatch.html",
        "single HTML file",
        "No external services required (no database, no Redis)",
    )

    for claim in stale_claims:
        assert claim not in contributing
        assert claim not in security

    assert "open source for non-commercial use" not in readme.lower()
