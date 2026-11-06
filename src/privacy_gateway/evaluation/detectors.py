"""Component metrics before the pipeline merges overlapping categories."""

import math
import statistics
import time

from privacy_gateway.evaluation.metrics import detection_scores


def _span_scores(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
    }


def evaluate_components(detectors: dict, cases: list[dict], repeats: int = 5) -> dict:
    """Return typed exact-span precision/recall, case metrics and raw latency.

    No text or credential values are returned. Timing includes detector calls
    only, with one warmup per case. Samples are case-weighted, not traffic-weighted.
    """
    if repeats < 1 or not cases:
        raise ValueError("Provide cases and at least one timing repetition")
    if len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Case identifiers must be unique")
    if any(case["component"] not in detectors for case in cases):
        raise ValueError("Every case component must have a detector")
    report = {}
    for component, detector in detectors.items():
        selected = [case for case in cases if case["component"] == component]
        if not selected:
            continue
        observations = []
        times = []
        for case in selected:
            text = case["text"]
            expected = {(item["category"], item["start"], item["end"]) for item in case["expected"]}
            if any(not 0 <= start < end <= len(text) for _, start, end in expected):
                raise ValueError(f"Invalid expected span in {case['id']}")
            detector.detect(text)
            for _ in range(repeats):
                started = time.perf_counter_ns()
                findings = detector.detect(text)
                times.append((time.perf_counter_ns() - started) / 1_000_000)
            if any(not 0 <= f.start < f.end <= len(text) for f in findings):
                raise ValueError(f"Invalid detected span in {case['id']}")
            actual = {(f.category, f.start, f.end) for f in findings}
            observations.append((case["id"], expected, actual))
        categories = sorted({entry[0] for _, gold, actual in observations for entry in gold | actual})
        per_category = {}
        for category in categories:
            expected = [any(item[0] == category for item in gold) for _, gold, _ in observations]
            actual = [any(item[0] == category for item in found) for _, _, found in observations]
            per_category[category] = detection_scores(expected, actual)
        tp = sum(len(gold & found) for _, gold, found in observations)
        fp = sum(len(found - gold) for _, gold, found in observations)
        fn = sum(len(gold - found) for _, gold, found in observations)
        report[component] = {
            "cases": len(selected),
            "case_detection": detection_scores(
                [bool(gold) for _, gold, _ in observations],
                [bool(found) for _, _, found in observations],
            ),
            "per_category": per_category,
            "typed_exact_spans": _span_scores(tp, fp, fn),
            "mismatches": [
                {"id": id, "missing": sorted(gold - found), "extra": sorted(found - gold)}
                for id, gold, found in observations if gold != found
            ],
            "latency_ms": {
                "samples": len(times), "median": statistics.median(times),
                "p95": sorted(times)[math.ceil(0.95 * len(times)) - 1],
            },
        }
    return report
