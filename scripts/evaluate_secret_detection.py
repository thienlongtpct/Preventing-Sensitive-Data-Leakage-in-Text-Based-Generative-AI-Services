"""Evaluate structured-secret recognition and exact spans on synthetic cases."""

import argparse
import json
import subprocess
from pathlib import Path
from types import ModuleType

from privacy_gateway.detectors.structured_secrets import StructuredSecretDetector
from privacy_gateway.evaluation.metrics import detection_scores


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "src/privacy_gateway/detectors/secrets.py"


def evaluate(detector, cases: list[dict]) -> dict:
    expected_sensitive: list[bool] = []
    detected_sensitive: list[bool] = []
    expected_spans = 0
    exact_spans = 0
    for case in cases:
        findings = detector.detect(case["text"])
        expected_sensitive.append(bool(case["expected"]))
        detected_sensitive.append(bool(findings))
        for target in case["expected"]:
            expected_spans += 1
            start = case["text"].index(target["value"])
            end = start + len(target["value"])
            exact_spans += any(
                finding.detector == f"secrets:{target['kind']}"
                and finding.start == start
                and finding.end == end
                for finding in findings
            )
    return {
        "cases": len(cases),
        "positive_cases": sum(expected_sensitive),
        "negative_cases": len(cases) - sum(expected_sensitive),
        **detection_scores(expected_sensitive, detected_sensitive),
        "expected_spans": expected_spans,
        "exact_spans": exact_spans,
        "exact_span_recall": exact_spans / expected_spans if expected_spans else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=ROOT / "data/cases/structured_secret_cases.jsonl")
    parser.add_argument(
        "--baseline-ref",
        help="Also execute the secret detector from a trusted local Git commit or branch",
    )
    args = parser.parse_args()
    cases = [json.loads(line) for line in args.cases.read_text().splitlines() if line.strip()]
    report = {"current": evaluate(StructuredSecretDetector(), cases)}
    if args.baseline_ref:
        # This comparison is opt-in: a historical module is executable code.
        source = subprocess.run(
            ["git", "show", f"{args.baseline_ref}:{SOURCE}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        module = ModuleType("baseline_secrets")
        exec(compile(source, SOURCE, "exec"), module.__dict__)
        report["baseline"] = {"ref": args.baseline_ref, **evaluate(module.SecretDetector(), cases)}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
