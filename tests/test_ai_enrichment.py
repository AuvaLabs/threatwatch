"""Tests for the decoupled AI enrichment orchestrator.

Verifies that the four AI tiers run in order, that every tier is guarded
against exceptions, and that the circuit breaker is reset at the start of
each invocation so a short-lived out-of-band process starts clean.
"""
from unittest.mock import MagicMock, patch

from modules import ai_enrichment


class TestRunAiEnrichment:
    def _articles(self):
        return [
            {"title": "LockBit hit hospital", "link": "http://x/1"},
            {"title": "Gang leaked data", "link": "http://x/2"},
        ]

    def test_all_four_tiers_called_in_order(self):
        call_order = []
        with patch.object(ai_enrichment, "logger"), \
             patch("modules.briefing_generator.generate_briefing",
                   side_effect=lambda a: call_order.append("briefing")), \
             patch("modules.briefing_generator.generate_regional_briefings",
                   side_effect=lambda a: call_order.append("regional")), \
             patch("modules.briefing_generator.generate_top_stories",
                   side_effect=lambda a: call_order.append("top")), \
             patch("modules.briefing_generator.summarize_articles",
                   side_effect=lambda a: call_order.append("summaries")), \
             patch("modules.llm_client.reset_circuit"):
            ai_enrichment.run_ai_enrichment(self._articles())
        assert call_order == ["briefing", "regional", "top", "summaries"]

    def test_tier_failure_does_not_abort_remaining_tiers(self):
        called = []
        with patch("modules.briefing_generator.generate_briefing",
                   side_effect=RuntimeError("boom")), \
             patch("modules.briefing_generator.generate_regional_briefings",
                   side_effect=lambda a: called.append("regional")), \
             patch("modules.briefing_generator.generate_top_stories",
                   side_effect=lambda a: called.append("top")), \
             patch("modules.briefing_generator.summarize_articles",
                   side_effect=lambda a: called.append("summaries")), \
             patch("modules.llm_client.reset_circuit"):
            ai_enrichment.run_ai_enrichment(self._articles())
        # Briefing raised but remaining tiers still executed.
        assert called == ["regional", "top", "summaries"]

    def test_new_batch_defaults_to_all_articles(self):
        all_articles = self._articles()
        seen = {}
        with patch("modules.briefing_generator.generate_briefing"), \
             patch("modules.briefing_generator.generate_regional_briefings"), \
             patch("modules.briefing_generator.generate_top_stories"), \
             patch("modules.briefing_generator.summarize_articles",
                   side_effect=lambda a: seen.setdefault("batch", a)), \
             patch("modules.llm_client.reset_circuit"):
            ai_enrichment.run_ai_enrichment(all_articles)
        assert seen["batch"] is all_articles

    def test_new_batch_used_when_provided(self):
        all_articles = self._articles()
        new_batch = [{"title": "only new", "link": "http://x/3"}]
        seen = {}
        with patch("modules.briefing_generator.generate_briefing"), \
             patch("modules.briefing_generator.generate_regional_briefings"), \
             patch("modules.briefing_generator.generate_top_stories"), \
             patch("modules.briefing_generator.summarize_articles",
                   side_effect=lambda a: seen.setdefault("batch", a)), \
             patch("modules.llm_client.reset_circuit"):
            ai_enrichment.run_ai_enrichment(all_articles, new_batch=new_batch)
        assert seen["batch"] is new_batch

    def test_resets_circuit_breaker_at_start(self):
        reset_mock = MagicMock()
        with patch("modules.briefing_generator.generate_briefing"), \
             patch("modules.briefing_generator.generate_regional_briefings"), \
             patch("modules.briefing_generator.generate_top_stories"), \
             patch("modules.briefing_generator.summarize_articles"), \
             patch("modules.llm_client.reset_circuit", reset_mock):
            ai_enrichment.run_ai_enrichment(self._articles())
        assert reset_mock.called
