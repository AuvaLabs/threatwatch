from unittest.mock import patch

import scripts.backfill_summaries as backfill


def test_save_with_merge_persists_summary_metadata():
    corpus = [{"hash": "one", "title": "Story", "summary": ""}]
    generated = {
        "one": {
            "summary": "A grounded summary.",
            "intel_what": "data breach",
            "intel_who": None,
            "intel_impact": None,
        }
    }

    with patch.object(backfill, "_load", return_value=corpus), \
         patch.object(backfill, "persist_corpus") as persist:
        touched = backfill._save_with_merge(generated)

    assert touched == 1
    saved = persist.call_args.args[0]
    assert saved[0]["summary"] == "A grounded summary."
    assert saved[0]["summary_method"] == "ai"
    assert saved[0]["summary_generated"] is True
