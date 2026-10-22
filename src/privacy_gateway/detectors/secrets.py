import re

from privacy_gateway.schemas import Finding


SECRET_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"), "api_key", 0.99),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key", 0.99),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private_key", 1.0),
    (
        re.compile(r"(?i)\b(api[_-]?key|secret|access[_-]?token|password)\b\s*[:=]\s*([^\s,;]+)"),
        "assigned_secret",
        0.95,
    ),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*"), "bearer_token", 0.95),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "ssn", 0.99),
]


class SecretDetector:
    """Regular expressions for structured secrets and national identifiers."""

    name = "secrets"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, label, confidence in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                findings.append(
                    Finding(
                        category="secret",
                        detector=f"{self.name}:{label}",
                        start=match.start(),
                        end=match.end(),
                        severity="critical",
                        confidence=confidence,
                    )
                )
        findings.extend(_card_findings(text))
        return findings


def _card_findings(text: str) -> list[Finding]:
    pattern = re.compile(r"\b(?:\d[ -]?){13,19}\b")
    findings: list[Finding] = []
    for match in pattern.finditer(text):
        digits = [character for character in match.group() if character.isdigit()]
        if len(digits) not in {13, 15, 16} or not _luhn(digits):
            continue
        findings.append(
            Finding(
                category="secret",
                detector="secrets:card",
                start=match.start(),
                end=match.end(),
                severity="critical",
                confidence=0.99,
            )
        )
    return findings


def _luhn(digits: list[str]) -> bool:
    total = 0
    for index, character in enumerate(reversed(digits)):
        value = int(character)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0
