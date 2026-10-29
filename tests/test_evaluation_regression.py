"""Pardha Pudi's evaluation and regression testing contribution."""

import json
from types import SimpleNamespace

import pytest

from privacy_gateway.cli import main
from privacy_gateway.evaluation.metrics import detection_scores
from privacy_gateway.evaluation.runner import format_report, load_cases, run_evaluation
from privacy_gateway.schemas import Request


CASES = load_cases()


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_each_labeled_case_preserves_protection_and_benign_utility(gateway, case):
    """Name the failing case instead of hiding a regression in a single aggregate."""
    request = Request(case["text"], case["role"], case["service"])
    protected = gateway.handle(request, protected=True)
    unprotected = gateway.handle(request, protected=False)

    assert protected.sensitive == case["expect_sensitive"]
    assert protected.protected is True
    assert unprotected.protected is False
    assert protected.latency_ms >= 0
    assert unprotected.latency_ms >= 0
    if case["leak_strings"]:
        assert all(value not in (protected.output or "") for value in case["leak_strings"])
        # A blocked baseline would make the protection comparison uninformative.
        assert any(value in (unprotected.output or "") for value in case["leak_strings"])
    if not case["expect_sensitive"]:
        assert protected.action in {"allow", "warn"}
        assert protected.output


@pytest.mark.parametrize(
    "truth,predicted,counts,scores",
    [
        ([], [], (0, 0, 0, 0), (0, 0, 0, 0)),
        ([False, False], [False, False], (0, 0, 2, 0), (0, 0, 0, 0)),
        ([True, True], [False, False], (0, 0, 0, 2), (0, 0, 0, 0)),
        ([True, True], [True, True], (2, 0, 0, 0), (1, 1, 1, 0)),
        (
            [True, True, True, False, False, False],
            [True, True, False, True, False, False],
            (2, 1, 2, 1),
            (2 / 3, 2 / 3, 2 / 3, 1 / 3),
        ),
    ],
    ids=["empty", "only-negatives", "all-missed", "only-positives", "mixed-errors"],
)
def test_detection_metric_edge_cases(truth, predicted, counts, scores):
    result = detection_scores(truth, predicted)
    assert tuple(result[key] for key in ("tp", "fp", "tn", "fn")) == counts
    assert tuple(result[key] for key in ("precision", "recall", "f1", "fpr")) == pytest.approx(scores)


@pytest.mark.parametrize("truth,predicted", [([True], []), ([], [False])])
def test_detection_rejects_mismatched_labels(truth, predicted):
    with pytest.raises(ValueError):
        detection_scores(truth, predicted)


def test_runner_uses_attack_and_benign_denominators(gateway, monkeypatch):
    """Use deliberate misses, false positives and leaks to verify non-perfect scores."""
    cases = [
        {"id": "attack-a", "text": "probe-a", "role": "guest", "service": "chat",
         "expect_sensitive": True, "leakage_type": "retrieval", "leak_strings": ["FAKE-A"]},
        {"id": "attack-b", "text": "probe-b", "role": "employee", "service": "rag",
         "expect_sensitive": True, "leakage_type": "retrieval", "leak_strings": ["FAKE-B", "FAKE-C"]},
        {"id": "benign", "text": "hello", "role": "employee", "service": "agent",
         "expect_sensitive": False, "leak_strings": []},
        {"id": "benign-blocked", "text": "goodbye", "role": "guest", "service": "chat",
         "expect_sensitive": False, "leak_strings": []},
    ]
    calls = []
    results = iter([
        # Protected: one detected attack, one missed attack and one false positive.
        SimpleNamespace(output=None, action="block", sensitive=True, latency_ms=1.0),
        SimpleNamespace(output="FAKE-C", action="allow", sensitive=False, latency_ms=2.0),
        SimpleNamespace(output="hello", action="warn", sensitive=True, latency_ms=9.0),
        SimpleNamespace(output=None, action="block", sensitive=False, latency_ms=4.0),
        # Unprotected: both attack cases leak and the benign case succeeds.
        SimpleNamespace(output="FAKE-A", action="allow", sensitive=True, latency_ms=2.0),
        SimpleNamespace(output="FAKE-B FAKE-C", action="allow", sensitive=True, latency_ms=4.0),
        SimpleNamespace(output="hello", action="allow", sensitive=False, latency_ms=6.0),
        SimpleNamespace(output="goodbye", action="allow", sensitive=False, latency_ms=8.0),
    ])

    def handle(request, protected):
        calls.append((request, protected))
        return next(results)

    monkeypatch.setattr(gateway, "handle", handle)
    report = run_evaluation(gateway, cases)
    assert report["detection"] == {
        "tp": 1, "fp": 1, "tn": 1, "fn": 1,
        "precision": 0.5, "recall": 0.5, "f1": 0.5, "fpr": 0.5,
    }
    assert report["modes"]["protected"] == {
        "cases": 4, "attack_cases": 2, "benign_cases": 2,
        "attack_success": 0.5, "utility": 0.5, "mean_latency_ms": 4.0,
    }
    assert report["modes"]["unprotected"]["attack_success"] == 1.0
    assert report["modes"]["unprotected"]["utility"] == 1.0
    assert report["by_leakage_type"] == {"retrieval": {"protected": 0.5, "unprotected": 1.0}}
    assert [request for request, _ in calls[:4]] == [request for request, _ in calls[4:]]
    assert [protected for _, protected in calls] == [True] * 4 + [False] * 4
    # Reports carry metadata and decisions, never raw requests or model output.
    serialized = json.dumps(report)
    for raw_value in ("probe-a", "probe-b", "FAKE-A", "FAKE-B", "FAKE-C", "hello", "goodbye"):
        assert raw_value not in serialized


@pytest.mark.parametrize("cases", [[], [CASES[0]], [CASES[4]]], ids=["empty", "benign-only", "attack-only"])
def test_runner_handles_missing_metric_populations(gateway, cases):
    report = run_evaluation(gateway, cases)
    assert report["modes"]["protected"]["attack_success"] == 0
    if not cases:
        assert report["rows"] == []
        assert report["by_leakage_type"] == {}
        assert report["modes"]["protected"]["mean_latency_ms"] == 0
    if not cases or cases[0]["expect_sensitive"]:
        assert report["modes"]["protected"]["utility"] == 0
    if not cases or not cases[0]["leak_strings"]:
        assert report["modes"]["unprotected"]["attack_success"] == 0
    assert isinstance(format_report(report), str)


def test_evaluation_excludes_preexisting_audit_events(gateway):
    gateway.handle(Request("What are the office hours?", "employee"))
    report = run_evaluation(gateway, CASES[:1])
    assert len(gateway.audit.read_all()) == 3
    assert report["privacy"]["events"] == 2
    assert report["privacy"]["homomorphic_risk"]["count"] == 2


@pytest.mark.parametrize("as_json", [True, False], ids=["json", "text"])
def test_evaluate_cli_custom_cases_and_export(gateway, monkeypatch, tmp_path, capsys, as_json):
    monkeypatch.setattr("privacy_gateway.cli.build_gateway", lambda: gateway)
    cases_path = tmp_path / "cases.jsonl"
    cases_path.write_text(json.dumps(CASES[0]) + "\n", encoding="utf-8")
    output_path = tmp_path / "reports" / "evaluation.json"
    arguments = ["evaluate", "--cases", str(cases_path), "--output", str(output_path)]
    if as_json:
        arguments.append("--json")
    assert main(arguments) == 0
    stdout = capsys.readouterr().out
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["modes"]["protected"]["cases"] == 1
    assert report["modes"]["unprotected"]["cases"] == 1
    assert report["rows"][0]["service"] == "chat"
    assert report["rows"][0]["role"] == "employee"
    if as_json:
        assert json.loads(stdout) == report
    else:
        assert "Detection on protected runs" in stdout


def test_evaluate_cli_default_dataset(gateway, monkeypatch, capsys):
    monkeypatch.setattr("privacy_gateway.cli.build_gateway", lambda: gateway)
    assert main(["evaluate", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert len(report["rows"]) == 2 * len(CASES)
