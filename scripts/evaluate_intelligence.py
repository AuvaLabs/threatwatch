#!/usr/bin/env python3
"""Run the deterministic ThreatWatch intelligence benchmark."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.intelligence_eval import evaluate_dataset, load_dataset


DEFAULT_DATASET = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "intelligence_eval_v1.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--minimum-score", type=float, default=100.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = evaluate_dataset(load_dataset(args.dataset))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Intelligence evaluation: {result['score']:.2f}%")
        print(f"Cases: {result['summary']['passed_cases']}/{result['summary']['cases']}")
        for name, value in result["metrics"].items():
            print(f"{name}: {value:.2f}%")
        for case in result["cases"]:
            if not case["ok"]:
                print(f"FAIL {case['id']}: {'; '.join(case['failures'])}")
    return 0 if result["ok"] and result["score"] >= args.minimum_score else 1


if __name__ == "__main__":
    raise SystemExit(main())
