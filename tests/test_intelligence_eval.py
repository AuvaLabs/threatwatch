import json
from pathlib import Path

from modules.intelligence_eval import evaluate_dataset, load_dataset


FIXTURE = Path(__file__).parent / "fixtures" / "intelligence_eval_v1.json"


def test_golden_dataset_passes_all_incident_contracts():
    dataset = load_dataset(FIXTURE)

    result = evaluate_dataset(dataset)

    assert result["ok"] is True
    assert result["score"] == 100.0
    assert result["summary"]["cases"] >= 6
    assert result["metrics"]["merge_split_accuracy_pct"] == 100.0
    assert result["metrics"]["evidence_state_accuracy_pct"] == 100.0
    assert result["metrics"]["citation_integrity_pct"] == 100.0
    assert all(case["ok"] for case in result["cases"])


def test_failed_expectation_is_explained_without_raising():
    dataset = load_dataset(FIXTURE)
    changed = json.loads(json.dumps(dataset))
    changed["cases"][0]["expect"]["record_count"] = 99

    result = evaluate_dataset(changed)

    assert result["ok"] is False
    assert result["score"] < 100
    assert "record_count" in " ".join(result["cases"][0]["failures"])


def test_rejects_unknown_dataset_schema(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text('{"schema_version": 2, "cases": []}', encoding="utf-8")

    try:
        load_dataset(path)
    except ValueError as exc:
        assert "schema_version" in str(exc)
    else:
        raise AssertionError("unknown schema should be rejected")
