import pytest

from privacy_gateway.evaluation.metrics import detection_scores
from privacy_gateway.evaluation.runner import load_cases, run_evaluation
from privacy_gateway.privacy.differential import noisy_counts
from privacy_gateway.privacy.homomorphic import aggregate_risk_scores
from privacy_gateway.privacy.reporting import build_privacy_report


def test_detection_scores():
    perfect = detection_scores([True, False, True], [True, False, True])
    assert perfect["f1"] == 1
    assert perfect["fpr"] == 0
    false_positive = detection_scores([False], [True])
    assert false_positive["precision"] == 0
    assert false_positive["fpr"] == 1


def test_privacy_report_shapes():
    with pytest.raises(ValueError):
        noisy_counts({"block": 2}, epsilon=0)
    first = noisy_counts({"block": 2, "allow": 1}, epsilon=1.0, seed=7)
    second = noisy_counts({"block": 2, "allow": 1}, epsilon=1.0, seed=7)
    assert first == second
    assert set(first) == {"block", "allow"}

    encrypted = aggregate_risk_scores([0.25, 0.5, 1.0])
    assert encrypted["count"] == 3
    assert encrypted["sum"] == pytest.approx(1.75, abs=0.05)

    report = build_privacy_report(
        [{"action": "block", "categories": ["secret"], "risk_score": 1.0}],
        epsilon=1.0,
    )
    assert report["events"] == 1
    assert report["homomorphic_risk"]["count"] == 1


def test_labeled_evaluation_stops_leaks_and_keeps_benign_utility(gateway):
    report = run_evaluation(gateway, load_cases(), epsilon=1.0)
    assert report["detection"]["f1"] == 1
    assert report["detection"]["fpr"] == 0
    assert report["modes"]["protected"]["attack_success"] == 0
    assert report["modes"]["protected"]["utility"] == 1
    assert report["modes"]["unprotected"]["attack_success"] == 1
    assert report["privacy"]["events"] == len(load_cases()) * 2
