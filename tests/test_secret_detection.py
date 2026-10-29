"""Structured-secret coverage and complete-span regressions, using fake values."""

import json
from pathlib import Path

import pytest

from privacy_gateway.detectors.secrets import SecretDetector
from privacy_gateway.detectors.structured_secrets import StructuredSecretDetector
from privacy_gateway.factory import build_gateway
from privacy_gateway.schemas import Finding, Request


CASES_PATH = Path(__file__).resolve().parents[1] / "data/cases/structured_secret_cases.jsonl"
CASES = [json.loads(line) for line in CASES_PATH.read_text().splitlines() if line.strip()]


def test_standard_factory_registers_the_extended_detector(gateway):
    detector = gateway.pipeline.detectors[0]
    assert type(detector) is StructuredSecretDetector
    assert isinstance(detector, SecretDetector)


def test_standard_factory_preserves_gateway_options(tmp_path):
    audit_path = tmp_path / "custom_audit.jsonl"
    gateway = build_gateway(
        root=Path(__file__).resolve().parents[1], audit_path=audit_path, protected=False,
    )
    assert gateway.audit.path == audit_path
    assert gateway.protected is False
    result = gateway.handle(Request("Synthetic SSN 123-45-6789.", "guest"))
    assert result.protected is False
    assert result.action == "allow"
    assert "123-45-6789" in result.output


def test_original_detector_remains_available_with_original_behavior():
    header = "-----BEGIN PRIVATE KEY-----"
    text = f"{header}\nFAKEBODY\n-----END PRIVATE KEY-----"
    original = SecretDetector().detect(text)
    extended = StructuredSecretDetector().detect(text)
    assert [text[f.start:f.end] for f in original] == [header]
    assert [text[f.start:f.end] for f in extended] == [text]


@pytest.mark.parametrize("text", ["Bearer FAKE.token_123456", "SSN 123-45-6789"])
def test_existing_unrefined_recognizers_pass_through(text):
    assert StructuredSecretDetector().detect(text) == SecretDetector().detect(text)


def test_additional_base_recognizers_are_preserved(monkeypatch):
    finding = Finding("secret", "secrets:future_format", 0, 7, "critical", 0.9)
    monkeypatch.setattr(SecretDetector, "detect", lambda self, text: [finding])
    assert StructuredSecretDetector().detect("payload") == [finding]


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_labeled_structured_secret(case):
    findings = StructuredSecretDetector().detect(case["text"])
    expected = case["expected"]
    assert bool(findings) == bool(expected)
    for target in expected:
        start = case["text"].index(target["value"])
        end = start + len(target["value"])
        assert any(
            finding.detector == f"secrets:{target['kind']}"
            and finding.start == start
            and finding.end == end
            for finding in findings
        ), f"Missing complete {target['kind']} span"
    assert all(0 <= finding.start < finding.end <= len(case["text"]) for finding in findings)
    assert all(finding.category == "secret" and finding.severity == "critical" for finding in findings)


@pytest.mark.parametrize("value", [" ", "   "])
def test_nonempty_whitespace_password_is_still_a_literal(value):
    text = f'password="{value}"'
    findings = StructuredSecretDetector().detect(text)
    assert len(findings) == 1
    assert text[findings[0].start:findings[0].end] == value


@pytest.mark.parametrize(
    "label",
    ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"],
)
def test_complete_private_key_block(label):
    block = f"-----BEGIN {label}-----\nAbCdEfGhIjKlMnOpQrStUvWxYz\n-----END {label}-----"
    text = f"Public introduction.\n{block}\nPublic conclusion."
    findings = [
        finding for finding in StructuredSecretDetector().detect(text)
        if finding.detector == "secrets:private_key"
    ]
    assert len(findings) == 1
    assert text[findings[0].start:findings[0].end] == block


def test_adjacent_private_key_blocks_keep_independent_spans():
    first = "-----BEGIN PRIVATE KEY-----\nFAKEFIRST\n-----END PRIVATE KEY-----"
    second = "-----BEGIN EC PRIVATE KEY-----\nFAKESECOND\n-----END EC PRIVATE KEY-----"
    text = f"{first}\nPublic separator.\n{second}"
    findings = StructuredSecretDetector().detect(text)
    assert [text[f.start:f.end] for f in findings] == [first, second]


def test_incomplete_private_key_stops_at_next_key():
    incomplete = "-----BEGIN PRIVATE KEY-----\nFAKEFIRST\n"
    complete = "-----BEGIN EC PRIVATE KEY-----\nFAKESECOND\n-----END EC PRIVATE KEY-----"
    text = incomplete + complete
    findings = StructuredSecretDetector().detect(text)
    assert [text[f.start:f.end] for f in findings] == [incomplete, complete]


@pytest.mark.parametrize("role", ["admin", "analyst"])
def test_gateway_removes_entire_private_key_and_preserves_public_text(gateway, role):
    body = "AbCdEfGhIjKlMnOpQrStUvWxYz" * 2
    block = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
    result = gateway.handle(Request(f"Public introduction.\n{block}\nPublic conclusion.", role))
    assert result.action == ("redact" if role == "admin" else "tokenize")
    assert result.output is not None
    assert body not in result.output
    assert "PRIVATE KEY" not in result.output
    assert "Public introduction." in result.output
    assert "Public conclusion." in result.output


@pytest.mark.parametrize("service", ["rag", "agent"])
def test_private_key_is_removed_from_context(gateway, service):
    body = "AbCdEfGhIjKlMnOpQrStUvWxYz" * 2
    record = {
        "sensitivity": "public",
        "text": f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----",
    }
    if service == "rag":
        gateway.retriever.docs = [{"id": "FAKE-KEY-RECORD", **record}]
        query = "Read FAKE-KEY-RECORD."
    else:
        gateway.tools.tools = {"FAKE-KEY-RECORD": record}
        query = "Read FAKE-KEY-RECORD."
    result = gateway.handle(Request(query, "admin", service))
    assert result.output is not None
    assert body not in result.output
    assert "[REDACTED:secret]" in result.output
    assert any(finding.source == "context" for finding in result.findings)


def test_private_key_is_removed_from_model_output(gateway):
    body = "AbCdEfGhIjKlMnOpQrStUvWxYz" * 2
    block = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"

    class LeakyOutput:
        def complete(self, user_text, context):
            return f"Public response.\n{block}"

    gateway.llm = LeakyOutput()
    result = gateway.handle(Request("Answer the support question.", "admin"))
    assert result.action == "redact"
    assert result.output == "Public response.\n[REDACTED:secret]"
    assert any(finding.source == "output" for finding in result.findings)


@pytest.mark.parametrize("role", ["guest", "employee"])
def test_private_key_still_blocks_stricter_roles(gateway, role):
    result = gateway.handle(Request("-----BEGIN PRIVATE KEY-----\nFAKEBODY", role))
    assert result.action == "block"
    assert result.output is None
