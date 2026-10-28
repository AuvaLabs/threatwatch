import json

from modules import command_brief
from modules import briefing_generator


def _briefing(provider="modelservices/gpt-6.1-sol", generated_at="2026-10-28T03:10:00+00:00"):
    return {
        "generated_at": generated_at,
        "provider": provider,
        "threat_level": "ELEVATED",
        "headline": "Current campaign activity",
        "what_happened": "A grounded assessment.",
        "what_to_do": ["Review exposed systems."],
        "source_articles": [
            {"index": 1, "title": "Source one", "link": "https://one.test/a"},
            {"index": 2, "title": "Source two", "link": "https://two.test/b"},
        ],
    }


def _paths(monkeypatch, tmp_path):
    monkeypatch.setattr(command_brief, "COMMAND_BRIEF_PATH", tmp_path / "command.json")
    monkeypatch.setattr(command_brief, "INTELLIGENCE_DELTA_PATH", tmp_path / "delta.json")
    monkeypatch.setattr(command_brief, "COMMAND_BRIEF_HISTORY_DIR", tmp_path / "history")


def test_sol_briefing_becomes_immutable_command_edition(monkeypatch, tmp_path):
    _paths(monkeypatch, tmp_path)

    assert command_brief.update_briefing_products(_briefing()) == "command_brief"

    current = json.loads(command_brief.COMMAND_BRIEF_PATH.read_text())
    history = list(command_brief.COMMAND_BRIEF_HISTORY_DIR.glob("*.json"))
    delta = json.loads(command_brief.INTELLIGENCE_DELTA_PATH.read_text())
    assert current["edition_type"] == "command_brief"
    assert current["edition_id"] == "20261028T031000Z"
    assert len(history) == 1
    assert json.loads(history[0].read_text()) == current
    assert delta == {
        "schema_version": 1,
        "available": False,
        "reason": "command_brief_current",
        "command_edition_id": "20261028T031000Z",
        "generated_at": "2026-10-28T03:10:00+00:00",
    }


def test_interim_briefing_writes_delta_without_replacing_command(monkeypatch, tmp_path):
    _paths(monkeypatch, tmp_path)
    command_brief.update_briefing_products(_briefing())
    command_before = command_brief.COMMAND_BRIEF_PATH.read_text()
    interim = _briefing(
        provider="anthropic/claude-sonnet-5-5",
        generated_at="2026-10-28T05:15:00+00:00",
    )
    interim["threat_level"] = "CRITICAL"
    interim["source_articles"].append(
        {"index": 3, "title": "New source", "link": "https://three.test/c"},
    )

    assert command_brief.update_briefing_products(interim) == "intelligence_delta"

    assert command_brief.COMMAND_BRIEF_PATH.read_text() == command_before
    delta = json.loads(command_brief.INTELLIGENCE_DELTA_PATH.read_text())
    assert delta["available"] is True
    assert delta["command_edition_id"] == "20261028T031000Z"
    assert delta["threat_level_changed"] is True
    assert delta["new_source_indexes"] == [3]
    assert delta["provider"] == "anthropic/claude-sonnet-5-5"


def test_invalid_or_ungrounded_briefing_is_not_published(monkeypatch, tmp_path):
    _paths(monkeypatch, tmp_path)
    invalid = _briefing()
    invalid["source_articles"] = []

    assert command_brief.update_briefing_products(invalid) is None
    assert not command_brief.COMMAND_BRIEF_PATH.exists()
    assert not command_brief.INTELLIGENCE_DELTA_PATH.exists()


def test_global_briefing_save_updates_command_products(monkeypatch, tmp_path):
    monkeypatch.setattr(briefing_generator, "BRIEFING_PATH", tmp_path / "briefing.json")

    briefing_generator._save_briefing(_briefing())

    command = json.loads((tmp_path / "command_brief.json").read_text())
    assert command["provider"] == "modelservices/gpt-6.1-sol"
    assert command["edition_type"] == "command_brief"
