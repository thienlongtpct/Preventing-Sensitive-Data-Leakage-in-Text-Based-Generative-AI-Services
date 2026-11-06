import pytest

from privacy_gateway.evaluation.detectors import evaluate_components
from privacy_gateway.schemas import Finding


def test_exact_span_precision_counts_extra_spans_in_positive_cases():
    class ExtraSpan:
        def detect(self, text):
            return [Finding("secret", "test", 0, 2, "high", 0.8),
                    Finding("secret", "test", 3, 5, "high", 0.8)]

    cases = [{"id": "synthetic", "component": "test", "text": "ab cd",
              "expected": [{"category": "secret", "start": 0, "end": 2}]}]
    report = evaluate_components({"test": ExtraSpan()}, cases, repeats=1)["test"]
    assert report["case_detection"]["f1"] == 1
    assert report["typed_exact_spans"]["precision"] == 0.5
    assert report["typed_exact_spans"]["recall"] == 1
    assert report["mismatches"] == [{"id": "synthetic", "missing": [], "extra": [("secret", 3, 5)]}]


def test_wrong_category_is_both_a_span_false_positive_and_false_negative():
    class WrongCategory:
        def detect(self, text):
            return [Finding("proprietary", "test", 0, 2, "high", 0.8)]

    cases = [{"id": "synthetic", "component": "test", "text": "ab",
              "expected": [{"category": "secret", "start": 0, "end": 2}]}]
    report = evaluate_components({"test": WrongCategory()}, cases, repeats=1)["test"]
    assert report["typed_exact_spans"]["fp"] == 1
    assert report["typed_exact_spans"]["fn"] == 1
    assert report["per_category"]["secret"]["fn"] == 1
    assert report["per_category"]["proprietary"]["fp"] == 1


def test_evaluator_rejects_empty_input_and_invalid_repetition_count():
    with pytest.raises(ValueError):
        evaluate_components({}, [])
    with pytest.raises(ValueError):
        evaluate_components({}, [{"id": "x"}], repeats=0)
