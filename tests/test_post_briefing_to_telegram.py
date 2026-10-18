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
