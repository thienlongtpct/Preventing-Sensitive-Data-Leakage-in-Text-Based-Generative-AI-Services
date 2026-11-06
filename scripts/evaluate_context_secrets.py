"""Compare original and extended detectors on synthetic development/challenge cases."""

import argparse
import json
import platform
from pathlib import Path

from privacy_gateway.detectors.context import HeuristicContextClassifier
from privacy_gateway.detectors.contextual_entropy import ContextualEntropyDetector
from privacy_gateway.detectors.entropy import EntropyDetector
from privacy_gateway.detectors.intent_context import IntentContextClassifier
from privacy_gateway.detectors.secrets import SecretDetector
from privacy_gateway.detectors.structured_secrets import StructuredSecretDetector
from privacy_gateway.evaluation.detectors import evaluate_components


ROOT = Path(__file__).resolve().parents[1]


def read_cases(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    datasets = parser.add_mutually_exclusive_group()
    datasets.add_argument("--challenge", action="store_true", help="Use the additional development challenge set")
    datasets.add_argument("--validation", action="store_true", help="Use the separate post-freeze validation set")
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    filename = (
        "detection_validation_cases.jsonl" if args.validation else
        "detection_challenge_cases.jsonl" if args.challenge else "context_secret_cases.jsonl"
    )
    cases = read_cases(ROOT / "data/cases" / filename)
    if not args.challenge and not args.validation:
        for case in read_cases(ROOT / "data/cases/structured_secret_cases.jsonl"):
            targets = []
            for item in case["expected"]:
                start = case["text"].index(item["value"])
                targets.append({"category": "secret", "start": start, "end": start + len(item["value"])})
            cases.append({**case, "component": "structured", "expected": targets})
    report = {
        "dataset": filename, "synthetic": True,
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "baseline": evaluate_components({
            "structured": SecretDetector(), "entropy": EntropyDetector(),
            "context": HeuristicContextClassifier(),
        }, cases, args.repeats),
        "current": evaluate_components({
            "structured": StructuredSecretDetector(), "entropy": ContextualEntropyDetector(),
            "context": IntentContextClassifier(),
        }, cases, args.repeats),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
