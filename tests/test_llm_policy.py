from modules.llm_policy import caller_enabled


def test_routine_callers_follow_pipeline_toggle(monkeypatch):
    monkeypatch.setenv("ROUTINE_LLM_ENABLED", "0")

    assert caller_enabled("classify") is False
    assert caller_enabled("attack_llm") is False
    assert caller_enabled("actor_profile") is False


def test_operational_briefings_are_never_deferred(monkeypatch):
    monkeypatch.setenv("ROUTINE_LLM_ENABLED", "0")

    assert caller_enabled("briefing") is True
    assert caller_enabled("regional") is True
    assert caller_enabled("top_stories") is True
    assert caller_enabled("summaries") is True


def test_routine_callers_default_to_enabled(monkeypatch):
    monkeypatch.delenv("ROUTINE_LLM_ENABLED", raising=False)

    assert caller_enabled("ttp_extract") is True
