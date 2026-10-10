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

    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24" not in workflow
    assert "ubuntu-latest" not in workflow
    assert workflow.count("runs-on: ubuntu-24.04") == 5


def test_generated_public_payloads_are_ignored():
    ignore_rules = _read(".gitignore").splitlines()

    assert "docs/index.html" in ignore_rules
    assert "docs/articles.json" in ignore_rules


def test_python_lock_source_respects_runtime_compatibility():
    requirements = _read("requirements.in")
    python_version = _read(".python-version").strip()

    assert "lingua-language-detector>=2.0,<2.2" in requirements
    assert python_version == "3.11"


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


def test_release_scripts_fail_closed_and_verify_recovery():
    deploy = _read("scripts/deploy.sh")
    backup = _read("scripts/backup_volume.sh")
    verify = _read("scripts/verify_backup.sh")
    dockerfile = _read("Dockerfile")

    assert "/api/v1/health" in deploy
    assert "|| true" not in deploy
    assert "TW_HEALTH_TIMEOUT" in deploy
    assert '--build-arg "TW_BUILD_SHA=$EXPECTED_SHA"' in deploy
    assert '--build-arg "TW_BUILD_TIME=$BUILD_TIME"' in deploy
    assert "rollback" in deploy.lower()
    assert "verify_backup.sh" in backup
    assert 'pause "$WRITER_CONTAINER"' in backup
    assert 'unpause "$WRITER_CONTAINER"' in backup
    assert "sha256sum" in backup
    assert "verify_backup.py" in verify
    assert dockerfile.index("RUN pip install") < dockerfile.index("ARG TW_BUILD_SHA")
