from privacy_gateway.policy.actions import apply_transforms
from privacy_gateway.policy.engine import PolicyEngine
from privacy_gateway.schemas import Finding


ROLES = {
    "guest": {"critical": "block", "high": "block", "medium": "redact", "low": "warn"},
    "employee": {"critical": "block", "high": "redact", "medium": "redact", "low": "allow"},
    "analyst": {"critical": "tokenize", "high": "warn", "medium": "warn", "low": "allow"},
}


def test_most_restrictive_action_wins():
    engine = PolicyEngine(ROLES)
    findings = [
        Finding("pii", "entities", 0, 4, "medium", 0.9),
        Finding("secret", "secrets", 5, 9, "critical", 0.99),
    ]
    decision = engine.decide("guest", findings)
    assert decision.action == "block"
    assert engine.decide("analyst", findings).action == "tokenize"
    assert engine.decide("employee", []).action == "allow"
    assert engine.decide("stranger", findings).unknown_role is True


def test_redact_and_tokenize_remove_the_secret_value():
    finding = Finding("secret", "secrets", 5, 11, "critical", 1.0)
    redacted = apply_transforms("keep secret keep", [(finding, "redact")], "dev-key")
    tokenized = apply_transforms("keep secret keep", [(finding, "tokenize")], "dev-key")
    assert redacted == "keep [REDACTED:secret] keep"
    assert "secret" not in tokenized.split("[TOKEN:secret:")[1]
    assert tokenized.startswith("keep [TOKEN:secret:")
