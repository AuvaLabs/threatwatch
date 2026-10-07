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

    def test_reset_circuit_exception_swallowed(self):
        """reset_circuit raising must not break the enrichment run — the
        breaker reset is best-effort."""
        with patch("modules.briefing_generator.generate_briefing"), \
             patch("modules.briefing_generator.generate_regional_briefings"), \
             patch("modules.briefing_generator.generate_top_stories"), \
             patch("modules.briefing_generator.summarize_articles"), \
             patch("modules.llm_client.reset_circuit",
                   side_effect=ImportError("module gone")):
            # Should not raise.
            ai_enrichment.run_ai_enrichment(self._articles())

    def test_regional_failure_does_not_abort(self):
        called = []
        with patch("modules.briefing_generator.generate_briefing"), \
             patch("modules.briefing_generator.generate_regional_briefings",
                   side_effect=RuntimeError("regional boom")), \
             patch("modules.briefing_generator.generate_top_stories",
                   side_effect=lambda a: called.append("top")), \
             patch("modules.briefing_generator.summarize_articles",
                   side_effect=lambda a: called.append("summaries")), \
             patch("modules.llm_client.reset_circuit"):
            ai_enrichment.run_ai_enrichment(self._articles())
        assert called == ["top", "summaries"]

    def test_top_stories_failure_does_not_abort_summaries(self):
        called = []
        with patch("modules.briefing_generator.generate_briefing"), \
             patch("modules.briefing_generator.generate_regional_briefings"), \
             patch("modules.briefing_generator.generate_top_stories",
                   side_effect=RuntimeError("top boom")), \
             patch("modules.briefing_generator.summarize_articles",
                   side_effect=lambda a: called.append("summaries")), \
             patch("modules.llm_client.reset_circuit"):
            ai_enrichment.run_ai_enrichment(self._articles())
        assert called == ["summaries"]

    def test_summaries_failure_does_not_raise(self):
        """The final tier raising should still leave the function returning
        cleanly (never raises — guarded)."""
        with patch("modules.briefing_generator.generate_briefing"), \
             patch("modules.briefing_generator.generate_regional_briefings"), \
             patch("modules.briefing_generator.generate_top_stories"), \
             patch("modules.briefing_generator.summarize_articles",
                   side_effect=RuntimeError("summaries boom")), \
             patch("modules.llm_client.reset_circuit"):
            # Should not raise.
            ai_enrichment.run_ai_enrichment(self._articles())

    def test_returns_structured_tier_status(self):
        with patch("modules.briefing_generator.generate_briefing", return_value={"headline": "ok"}), \
             patch("modules.briefing_generator.generate_regional_briefings",
                   return_value={"na": {}, "emea": {}, "apac": {}}), \
             patch("modules.briefing_generator.generate_top_stories", return_value=[{"headline": "one"}]), \
             patch("modules.briefing_generator.summarize_articles", return_value=2), \
             patch("modules.llm_client.reset_circuit"):
            result = ai_enrichment.run_ai_enrichment(self._articles())

        assert result["global_briefing"]["ok"] is True
        assert result["regional_briefings"]["ok"] is True
        assert result["top_stories"]["ok"] is True
        assert result["article_summaries"]["ok"] is True
        assert result["article_summaries"]["count"] == 2

    def test_failure_is_reported_without_sensitive_error_detail(self):
        with patch("modules.briefing_generator.generate_briefing",
                   side_effect=RuntimeError("secret-key-123")), \
             patch("modules.briefing_generator.generate_regional_briefings"), \
             patch("modules.briefing_generator.generate_top_stories"), \
             patch("modules.briefing_generator.summarize_articles"), \
             patch("modules.llm_client.reset_circuit"):
            result = ai_enrichment.run_ai_enrichment(self._articles())

        assert result["global_briefing"] == {"ok": False, "error": "generation_failed"}

    def test_partial_regional_result_is_reported_failed(self):
        with patch("modules.briefing_generator.generate_briefing", return_value={"headline": "ok"}), \
             patch("modules.briefing_generator.generate_regional_briefings", return_value={"na": {}}), \
             patch("modules.briefing_generator.generate_top_stories", return_value=[{"headline": "one"}]), \
             patch("modules.briefing_generator.summarize_articles", return_value=0), \
             patch("modules.llm_client.reset_circuit"):
            result = ai_enrichment.run_ai_enrichment([
                {"title": "Already summarized", "summary": "done", "is_cyber_attack": True}
            ])

        assert result["regional_briefings"]["ok"] is False
        assert result["regional_briefings"]["missing"] == ["apac", "emea"]

    def test_zero_summaries_is_failure_when_work_was_pending(self):
        articles = [{"title": "Needs summary", "summary": "", "is_cyber_attack": True}]
        with patch("modules.briefing_generator.generate_briefing", return_value={"headline": "ok"}), \
             patch("modules.briefing_generator.generate_regional_briefings",
                   return_value={"na": {}, "emea": {}, "apac": {}}), \
             patch("modules.briefing_generator.generate_top_stories", return_value=[{"headline": "one"}]), \
             patch("modules.briefing_generator.summarize_articles", return_value=0), \
             patch("modules.llm_client.reset_circuit"):
            result = ai_enrichment.run_ai_enrichment(articles)

        assert result["article_summaries"]["ok"] is False
        assert result["article_summaries"]["pending"] == 1
