"""Persistence contract for the out-of-band enrichment command."""

from unittest.mock import patch

from scripts import run_ai_enrichment


def test_run_persists_mutated_article_corpus():
    articles = [{"hash": "one", "title": "Report", "summary": ""}]

    def enrich(items):
        items[0]["summary"] = "Generated summary"
        return {"article_summaries": {"ok": True, "count": 1}}

    with patch("modules.output_writer.load_existing", return_value=articles), \
         patch("modules.output_writer.persist_corpus") as persist, \
         patch("modules.safe_http.install_ssrf_guard"), \
         patch("modules.ai_enrichment.run_ai_enrichment", side_effect=enrich):
        result = run_ai_enrichment.main()

    persist.assert_called_once_with(articles)
    assert result["article_summaries"]["count"] == 1
