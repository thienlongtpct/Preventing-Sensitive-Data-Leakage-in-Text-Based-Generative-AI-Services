import re

from privacy_gateway.schemas import Finding


EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")

PRESIDIO_MAP = {
    "EMAIL_ADDRESS": ("pii", "medium", 0.9),
    "PHONE_NUMBER": ("pii", "medium", 0.85),
    "PERSON": ("pii", "low", 0.6),
    "CREDIT_CARD": ("secret", "critical", 0.95),
    "US_SSN": ("secret", "critical", 0.95),
    "IP_ADDRESS": ("pii", "medium", 0.7),
    "LOCATION": ("pii", "low", 0.5),
}


class EntityDetector:
    """Contact-entity patterns, plus Presidio when that package is installed."""

    name = "entities"

    def __init__(self, use_presidio: bool = True):
        self._analyzer = None
        if use_presidio:
            try:
                from presidio_analyzer import AnalyzerEngine

                self._analyzer = AnalyzerEngine()
            except Exception:
                self._analyzer = None

    def detect(self, text: str) -> list[Finding]:
        findings = [
            *_pattern_findings(text, EMAIL, "email", 0.9),
            *_pattern_findings(text, PHONE, "phone", 0.85),
        ]
        if self._analyzer is None:
            return findings
        try:
            results = self._analyzer.analyze(text=text, language="en")
        except Exception:
            return findings
        for result in results:
            category, severity, confidence = PRESIDIO_MAP.get(
                result.entity_type, ("pii", "low", float(result.score))
            )
            findings.append(
                Finding(
                    category=category,
                    detector=f"presidio:{result.entity_type}",
                    start=result.start,
                    end=result.end,
                    severity=severity,
                    confidence=max(confidence, float(result.score)),
                )
            )
        return findings


def _pattern_findings(text: str, pattern: re.Pattern[str], label: str, confidence: float) -> list[Finding]:
    return [
        Finding(
            category="pii",
            detector=f"entities:{label}",
            start=match.start(),
            end=match.end(),
            severity="medium",
            confidence=confidence,
        )
        for match in pattern.finditer(text)
    ]


class SpacyNameDetector:
    """Optional spaCy person-name detector. Off unless a model is already installed."""

    name = "spacy"

    def __init__(self, model: str = "en_core_web_sm", enabled: bool = False):
        self.enabled = enabled
        self._nlp = None
        if not enabled:
            return
        try:
            import spacy

            self._nlp = spacy.load(model)
        except Exception:
            self._nlp = None

    def detect(self, text: str) -> list[Finding]:
        if self._nlp is None:
            return []
        document = self._nlp(text)
        return [
            Finding(
                category="pii",
                detector="spacy:person",
                start=ent.start_char,
                end=ent.end_char,
                severity="low",
                confidence=0.7,
            )
            for ent in document.ents
            if ent.label_ == "PERSON"
        ]
