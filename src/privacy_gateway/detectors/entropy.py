import math
import re

from privacy_gateway.schemas import Finding


TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


class EntropyDetector:
    """Flag long, high-entropy tokens that pattern rules did not name."""

    name = "entropy"

    def __init__(self, threshold: float = 3.8, min_length: int = 20):
        self.threshold = threshold
        self.min_length = min_length

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in TOKEN.finditer(text):
            token = match.group()
            if len(token) < self.min_length or not _mixed_token(token):
                continue
            score = shannon_entropy(token)
            if score < self.threshold:
                continue
            findings.append(
                Finding(
                    category="secret",
                    detector=self.name,
                    start=match.start(),
                    end=match.end(),
                    severity="high",
                    confidence=min(0.95, score / 6),
                )
            )
        return findings


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _mixed_token(value: str) -> bool:
    return any(character.islower() for character in value) and any(
        character.isupper() for character in value
    ) and any(character.isdigit() for character in value)
