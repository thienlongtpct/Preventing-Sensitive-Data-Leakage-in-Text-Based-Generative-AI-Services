import re

from privacy_gateway.detectors.secrets import SecretDetector, _luhn
from privacy_gateway.schemas import Finding


STRUCTURED_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r"(?<![\w-])sk-[A-Za-z0-9_-]{16,}(?![\w-])"), "api_key", 0.99),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "aws_access_key", 0.99),
]

# Only these recognizers are refined. Other findings from the original detector,
# including future recognizers, pass through unchanged.
REFINED_RECOGNIZERS = {
    "secrets:api_key",
    "secrets:aws_access_key",
    "secrets:private_key",
    "secrets:assigned_secret",
    "secrets:card",
}

PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?P<label>(?:[A-Z0-9]+ )*PRIVATE KEY)-----")
CARD = re.compile(r"(?<!\w)[0-9](?:[ -]?[0-9]){12,}(?![ -]?[0-9]|\w)")

# Preserve field names and quotes: the finding covers the credential value.
# Structured atoms keep references and gateway placeholders together so that an
# exact placeholder can be distinguished from a placeholder plus a literal suffix.
ASSIGNED_SECRET = re.compile(
    r'''(?ixm)
    (?<![\w-])(?P<quote>["']?)
    (?:api[_-]?key|client[_-]?secret|secret[_-]?key|secret|
       access[_-]?token|auth[_-]?token|refresh[_-]?token|password|passwd)
    (?P=quote)(?![\w-])[ \t]*[:=][ \t]*
    (?:
        "(?P<double>(?:\\[^\r\n]|[^"\\\r\n])*)(?:"|(?=\r?$))
        |'(?P<single>(?:\\[^\r\n]|[^'\\\r\n])*)(?:'|(?=\r?$))
        |(?P<bare>(?:\$\{[^}\s]*\}|\[(?:REDACTED|TOKEN):[^\]\s]+\]|[^\s,;}\]"'])+)
    )
    '''
)
NON_LITERAL = re.compile(
    r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\[(?:REDACTED:[a-z_]+|TOKEN:[a-z_]+:[0-9a-f]{8})\])"
)


class StructuredSecretDetector(SecretDetector):
    """Extend the original detector with complete structured-secret spans.

    The base detector remains available with its original behavior. This adapter
    refines selected recognizers and preserves all other base findings.
    A format or checksum match is evidence of sensitivity, not proof that a
    credential is active or an identifier belongs to a real person.
    """

    def detect(self, text: str) -> list[Finding]:
        findings = [
            finding for finding in super().detect(text)
            if finding.detector not in REFINED_RECOGNIZERS
        ]
        for pattern, label, confidence in STRUCTURED_PATTERNS:
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
        findings.extend(_private_key_findings(text))
        findings.extend(_assignment_findings(text))
        findings.extend(_card_findings(text))
        return findings


def _private_key_findings(text: str) -> list[Finding]:
    headers = list(PRIVATE_KEY_HEADER.finditer(text))
    findings: list[Finding] = []
    for index, header in enumerate(headers):
        limit = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        footer = f"-----END {header.group('label')}-----"
        footer_start = text.find(footer, header.end(), limit)
        # An incomplete block remains sensitive through the next block or EOF.
        end = footer_start + len(footer) if footer_start >= 0 else limit
        findings.append(
            Finding("secret", "secrets:private_key", header.start(), end, "critical", 1.0)
        )
    return findings


def _assignment_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in ASSIGNED_SECRET.finditer(text):
        group = next(name for name in ("double", "single", "bare") if match.group(name) is not None)
        value = match.group(group)
        if not value or NON_LITERAL.fullmatch(value):
            continue
        if group == "bare" and value.lower() in {"null", "none"}:
            continue
        findings.append(
            Finding("secret", "secrets:assigned_secret", *match.span(group), "critical", 0.95)
        )
    return findings


def _card_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in CARD.finditer(text):
        digits = [character for character in match.group() if character.isdigit()]
        if not 13 <= len(digits) <= 19 or len(set(digits)) == 1 or not _luhn(digits):
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
