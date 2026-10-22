import re

from privacy_gateway.schemas import Finding


# Document-level stand-in for the transformer or LLM classifier in the proposal.
# A match treats the whole request as sensitive until a model can return tighter spans.
INTENT_RULES: list[tuple[re.Pattern[str], str, str, float]] = [
    (
        re.compile(r"(?i)ignore (all |any )?(previous|prior) instructions"),
        "prompt_injection",
        "high",
        0.9,
    ),
    (
        re.compile(
            r"(?i)(reveal|print|show|repeat|dump).{0,48}(system prompt|hidden instructions|developer message)"
        ),
        "system_instruction",
        "high",
        0.88,
    ),
    (
        re.compile(r"(?i)\b(system prompt|hidden instructions|developer message)\b"),
        "system_instruction",
        "high",
        0.8,
    ),
    (
        re.compile(r"(?i)\b(memorized|training data|canary passphrase|canary)\b"),
        "memorized",
        "high",
        0.8,
    ),
    (
        re.compile(r"(?i)\b(confidential|internal use only|do not distribute|proprietary)\b"),
        "proprietary",
        "high",
        0.75,
    ),
    (
        re.compile(r"(?i)\b(salary|compensation|social security number|bank account|card number)\b"),
        "retrieval",
        "high",
        0.75,
    ),
]


class HeuristicContextClassifier:
    """Keyword and phrase classifier used until a fine-tuned model is plugged in."""

    name = "context"

    def detect(self, text: str) -> list[Finding]:
        if not text:
            return []
        findings: list[Finding] = []
        for pattern, category, severity, confidence in INTENT_RULES:
            if pattern.search(text):
                findings.append(
                    Finding(
                        category=category,
                        detector=self.name,
                        start=0,
                        end=len(text),
                        severity=severity,
                        confidence=confidence,
                    )
                )
        return findings


class TransformerContextClassifier:
    """Plug-in point for a fine-tuned sequence or text classifier.

    The default gateway uses HeuristicContextClassifier so the project runs
    without model weights. Implement `detect` when labeled training data exists.
    """

    name = "transformer"

    def detect(self, text: str) -> list[Finding]:
        raise NotImplementedError(
            "No transformer weights are bundled. Use HeuristicContextClassifier "
            "or load a local fine-tuned model in this method."
        )
