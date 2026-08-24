"""Run the deterministic explanation baseline against synthetic fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evaluation import evaluate_explanation, summarize  # noqa: E402
from main import local_explanation  # noqa: E402


def main() -> int:
    cases = json.loads((ROOT / "fixtures" / "exposure_cases.json").read_text(encoding="utf-8"))
    results = [
        evaluate_explanation(case, local_explanation(case["scan_data"]))
        for case in cases
    ]
    summary = summarize(results)
    output = ROOT / "results" / "local-baseline.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in summary.items() if key != "results"}, indent=2))
    return 0 if summary["cases_with_canary_leakage"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
