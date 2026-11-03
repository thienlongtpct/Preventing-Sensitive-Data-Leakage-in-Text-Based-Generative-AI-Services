"""Local evidence rules for unstructured credential candidates."""

import re

from privacy_gateway.detectors.entropy import EntropyDetector, shannon_entropy
from privacy_gateway.schemas import Finding


# Boundaries prevent extracting a convincing substring from a longer identifier.
CANDIDATE = re.compile(r"(?<![\w+/-])[A-Za-z0-9+/_-]+={0,2}(?![\w+/=-])")
CREDENTIAL_CUE = re.compile(
    r"(?i)\b(?:password|passwd|passphrase|secret|credential|"
    r"(?:api|access|auth|refresh|session|client)[_ -]?(?:key|token|secret)|token)\b"
)
PUBLIC_CUE = re.compile(
    r"(?i)\b(?:sha(?:1|224|256|384|512)?|md5|checksum|digest|hash|"
    r"commit|uuid|guid|request[_ -]?id|trace[_ -]?id|public[_ -]?id)\b"
)
HEX = re.compile(r"[0-9a-fA-F]+")
UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
REFERENCE = re.compile(r"\$\{[^}\r\n]+\}|\[(?:REDACTED|TOKEN):[^]\r\n]+\]")


class ContextualEntropyDetector(EntropyDetector):
    """Combine token structure, Shannon entropy and nearby credential evidence.

    Unlabelled candidates retain the original mixed-case/digit requirement.
    A credential cue admits other alphabets; entropy alone cannot prove secrecy.
    Public identifiers are suppressed only in this heuristic, never in the
    independent structured-secret detector. Confidence is not calibrated.
    """

    def __init__(self, threshold: float = 3.8, min_length: int = 20):
        if threshold <= 0 or min_length < 1:
            raise ValueError("Entropy threshold and minimum length must be positive")
        super().__init__(threshold, min_length)

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        references = [match.span() for match in REFERENCE.finditer(text)]
        for match in CANDIDATE.finditer(text):
            token = match.group()
            if len(token) < self.min_length or any(
                start <= match.start() and match.end() <= end for start, end in references
            ):
                continue
            # Evidence belongs to this value's clause, not another line/field.
            prefix = re.split(r"[\n\r,;.!?]", text[max(0, match.start() - 64):match.start()])[-1]
            credential = bool(CREDENTIAL_CUE.search(prefix))
            public = bool(PUBLIC_CUE.search(prefix))
            if not credential and (public or UUID.fullmatch(token) or HEX.fullmatch(token)):
                continue
            # URL/path components and snake-case names are common public tokens.
            if not credential and (
                re.search(r"(?:https?://|[/\\])\S*$", text[max(0, match.start() - 128):match.start()])
                or token.startswith("/") or "_" in token
            ):
                continue
            lower = any(c.islower() for c in token)
            upper = any(c.isupper() for c in token)
            digit = any(c.isdigit() for c in token)
            if not credential and not (lower and upper and digit):
                continue
            score = shannon_entropy(token.rstrip("="))
            # Hex has a four-bit alphabet; cued hex uses a separate threshold.
            threshold = min(self.threshold, 3.0) if credential and HEX.fullmatch(token) else self.threshold
            if score < threshold:
                continue
            findings.append(Finding(
                "secret", self.name, match.start(), match.end(), "high",
                0.85 if credential else 0.65,
            ))
        return findings
