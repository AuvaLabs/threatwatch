from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_threatfox_key_is_loaded_from_a_dedicated_secret_file():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    pipeline = compose["services"]["pipeline"]

    secret_paths = {
        entry.get("path")
        for entry in pipeline["env_file"]
        if isinstance(entry, dict)
    }
    environment = pipeline.get("environment", [])

    assert "${THREATFOX_ENV_FILE:-.secrets/threatfox.env}" in secret_paths
    assert not any(value.startswith("THREATFOX_AUTH_KEY=") for value in environment)


def test_threatfox_secret_file_is_documented_without_a_real_key():
    example = (ROOT / ".env.example").read_text(encoding="utf-8")

    assert "THREATFOX_ENV_FILE=.secrets/threatfox.env" in example
    assert "THREATFOX_AUTH_KEY=your-threatfox-auth-key" in example
