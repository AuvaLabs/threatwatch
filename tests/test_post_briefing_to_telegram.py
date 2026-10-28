"""Daily Telegram poster validation tests."""

import json

from scripts import post_briefing_to_telegram as poster


def test_dry_run_validates_configuration_without_posting(tmp_path, monkeypatch, capsys):
    briefing = tmp_path / "briefing.json"
    briefing.write_text(json.dumps({"threat_level": "ELEVATED"}))
    monkeypatch.setattr(poster, "BRIEFING_PATH", briefing)
    monkeypatch.setattr(poster, "setup_logger", lambda: None)
    monkeypatch.setattr("modules.telegram.TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setattr("modules.telegram.TELEGRAM_CHAT_ID", "chat")
    post = monkeypatch.setattr(
        "modules.telegram.post_briefing_unconditional",
        lambda payload: (_ for _ in ()).throw(AssertionError("must not post")),
    )

    assert poster.main(dry_run=True) == 0
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "dry_run": True,
        "level": "ELEVATED",
        "destination_configured": True,
    }
    assert post is None


def test_command_brief_is_preferred_over_live_briefing(tmp_path, monkeypatch):
    command = tmp_path / "command_brief.json"
    live = tmp_path / "briefing.json"
    command.write_text(json.dumps({"threat_level": "CRITICAL"}))
    live.write_text(json.dumps({"threat_level": "LOW"}))
    monkeypatch.setattr(poster, "COMMAND_BRIEF_PATH", command)
    monkeypatch.setattr(poster, "BRIEFING_PATH", live)

    loaded = poster._load_briefing(poster.logging.getLogger("test"), dry_run=True)

    assert loaded == {"threat_level": "CRITICAL"}
