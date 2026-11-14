import logging
import os
import subprocess
import sys

from modules import config


def test_daily_budget_defaults_to_four_dollars():
    env = os.environ.copy()
    env.pop("DAILY_BUDGET_USD", None)

    result = subprocess.run(
        [sys.executable, "-c", "from modules.config import DAILY_BUDGET_USD; print(DAILY_BUDGET_USD)"],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.stdout.strip() == "4.0"


def test_validate_config_reports_native_anthropic(monkeypatch, caplog):
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(config, "LLM_API_KEY", "")

    with caplog.at_level(logging.INFO, logger=config.__name__):
        config.validate_config()

    assert "native Anthropic" in caplog.text


def test_validate_config_reports_disabled_without_any_key(monkeypatch, caplog):
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "")
    monkeypatch.setattr(config, "LLM_API_KEY", "")

    with caplog.at_level(logging.INFO, logger=config.__name__):
        config.validate_config()

    assert "AI features disabled" in caplog.text
