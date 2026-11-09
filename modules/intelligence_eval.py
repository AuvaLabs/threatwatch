"""Golden-case evaluation for deterministic intelligence behavior."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from modules.date_utils import parse_datetime
from modules.incident_records import build_incident_records


DATASET_SCHEMA_VERSION = 1


def load_dataset(path: Path | str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != DATASET_SCHEMA_VERSION:
        raise ValueError(f"unsupported intelligence evaluation schema_version: {payload.get('schema_version')}")
    if not isinstance(payload.get("cases"), list) or not payload["cases"]:
        raise ValueError("intelligence evaluation dataset must contain cases")
    return payload


def evaluate_dataset(dataset: dict[str, Any]) -> dict[str, Any]:
    generated_at = parse_datetime(dataset.get("generated_at"))
    results = [_evaluate_case(case, generated_at) for case in dataset.get("cases", [])]
    assertions = sum(result["assertions"] for result in results)
    passed = sum(result["passed_assertions"] for result in results)
    score = round(passed / assertions * 100, 2) if assertions else 0.0
    citation_total = sum(result["citation_total"] for result in results)
    citation_valid = sum(result["citation_valid"] for result in results)
    merge_cases = [result for result in results if result["merge_split_checked"]]
    state_cases = [result for result in results if result["evidence_state_checked"]]
    return {
        "schema_version": DATASET_SCHEMA_VERSION,
        "ok": bool(results) and all(result["ok"] for result in results),
        "score": score,
        "summary": {
            "cases": len(results),
            "passed_cases": sum(result["ok"] for result in results),
            "assertions": assertions,
            "passed_assertions": passed,
        },
        "metrics": {
            "merge_split_accuracy_pct": _percent(sum(result["merge_split_ok"] for result in merge_cases), len(merge_cases)),
            "evidence_state_accuracy_pct": _percent(sum(result["evidence_state_ok"] for result in state_cases), len(state_cases)),
            "citation_integrity_pct": _percent(citation_valid, citation_total),
        },
        "cases": results,
    }


def _evaluate_case(case: dict[str, Any], generated_at: datetime | None) -> dict[str, Any]:
    payload = build_incident_records(case.get("articles", []), generated_at=generated_at)
    records = payload["records"]
    expected = case.get("expect", {})
    checks: list[tuple[str, bool]] = []
    if "record_count" in expected:
        checks.append((f"record_count expected {expected['record_count']} got {len(records)}", len(records) == expected["record_count"]))
    if "organizations" in expected:
        actual = sorted({record["organization"] for record in records})
        checks.append((f"organizations expected {expected['organizations']} got {actual}", actual == sorted(expected["organizations"])))
    if "event_types" in expected:
        actual = sorted(record["event_type"] for record in records)
        checks.append((f"event_types expected {expected['event_types']} got {actual}", actual == sorted(expected["event_types"])))
    state_checks = []
    for spec in expected.get("records", []):
        record = _find_record(records, spec)
        checks.append((f"record not found for {spec.get('organization', 'expectation')}", record is not None))
        if record is not None:
            record_checks = _record_checks(record, spec)
            checks.extend(record_checks)
            state_checks.extend(ok for label, ok in record_checks if any(term in label for term in ("state", "grade", "claim")))
    citation_total, citation_valid = _citation_counts(records)
    failures = [label for label, ok in checks if not ok]
    merge_checked = "record_count" in expected
    return {
        "id": case.get("id"), "description": case.get("description"),
        "ok": not failures, "failures": failures,
        "assertions": len(checks), "passed_assertions": sum(ok for _, ok in checks),
        "merge_split_checked": merge_checked,
        "merge_split_ok": bool(not failures or not merge_checked or checks[0][1]),
        "evidence_state_checked": bool(state_checks),
        "evidence_state_ok": all(state_checks) if state_checks else True,
        "citation_total": citation_total, "citation_valid": citation_valid,
    }


def _find_record(records: list[dict[str, Any]], spec: dict[str, Any]) -> dict[str, Any] | None:
    return next((record for record in records if (
        not spec.get("organization") or record.get("organization") == spec["organization"]
    ) and (
        not spec.get("event_type") or record.get("event_type") == spec["event_type"]
    )), None)


def _record_checks(record: dict[str, Any], spec: dict[str, Any]) -> list[tuple[str, bool]]:
    checks = []
    fields = ("state", "independent_source_count")
    for field in fields:
        if field in spec:
            checks.append((f"{field} expected {spec[field]} got {record.get(field)}", record.get(field) == spec[field]))
    if "evidence_grade" in spec:
        actual = record.get("evidence_assessment", {}).get("grade")
        checks.append((f"evidence_grade expected {spec['evidence_grade']} got {actual}", actual == spec["evidence_grade"]))
    if "authoritative_source_count" in spec:
        actual = record.get("evidence_assessment", {}).get("authoritative_source_count")
        checks.append((f"authoritative_source_count expected {spec['authoritative_source_count']} got {actual}", actual == spec["authoritative_source_count"]))
    if "maximum_score" in spec:
        checks.append((f"score expected <= {spec['maximum_score']} got {record.get('score')}", record.get("score", 0) <= spec["maximum_score"]))
    claims = record.get("claims", [])
    if "claim_subject" in spec:
        matched = [claim for claim in claims if claim.get("subject") == spec["claim_subject"]]
        checks.append((f"claim subject {spec['claim_subject']} missing", bool(matched)))
        if "claim_state" in spec:
            checks.append((f"claim state {spec['claim_state']} missing", any(claim.get("state") == spec["claim_state"] for claim in matched)))
        if "minimum_claims" in spec:
            checks.append((f"claim count expected >= {spec['minimum_claims']} got {len(matched)}", len(matched) >= spec["minimum_claims"]))
    if "missing_claim_statement" in spec:
        absent = all(claim.get("statement") != spec["missing_claim_statement"] for claim in claims)
        checks.append((f"claim should be absent: {spec['missing_claim_statement']}", absent))
    return checks


def _citation_counts(records: list[dict[str, Any]]) -> tuple[int, int]:
    total = valid = 0
    for record in records:
        source_ids = {source.get("article_id") for source in record.get("sources", [])}
        for claim in record.get("claims", []):
            total += 1
            claim_ids = claim.get("source_ids", [])
            valid += bool(claim_ids) and set(claim_ids) <= source_ids
    return total, valid


def _percent(numerator: int, denominator: int) -> float:
    return round(numerator / denominator * 100, 2) if denominator else 100.0
