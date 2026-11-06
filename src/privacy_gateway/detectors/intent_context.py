"""Deterministic action/target classification with original-text spans."""

import re
from bisect import bisect_left, bisect_right

from privacy_gateway.detectors.context import HeuristicContextClassifier
from privacy_gateway.schemas import Finding


ACTION = re.compile(
    r"(?i)\b(?:reveal|show|print|repeat|dump|disclose|expose|output|return|give|send|"
    r"display|list|read|retrieve|fetch|extract|copy|reproduce|complete|continue|recite|"
    r"quote|look\s+up|tell)\b"
)
TARGETS = {
    "system_instruction": re.compile(
        r"(?i)\b(?:system\s+(?:prompt|instructions)|hidden\s+(?:setup\s+)?instructions|"
        r"developer\s+(?:message|instructions)|initial\s+instructions|"
        r"original\s+(?:prompt|instructions)|"
        r"(?:instructions|directions|rules)\s+(?:you\s+(?:were\s+)?(?:given|received)|"
        r"given\s+to\s+you)\s+(?:before\s+(?:this|the)\s+(?:conversation|chat)|at\s+the\s+start))\b"
    ),
    "memorized": re.compile(
        r"(?i)\b(?:memoriz(?:ed|ation)|training\s+(?:data|examples|corpus)|"
        r"canary(?:\s+passphrase)?|verbatim\s+training\s+text)\b"
    ),
    "proprietary": re.compile(
        r"(?i)\b(?:confidential|internal\s+use\s+only|do\s+not\s+distribute|proprietary)\b"
    ),
    "retrieval": re.compile(
        r"(?i)\b(?:salary|compensation|social\s+security\s+number|bank\s+account|"
        r"card\s+number|payroll|medical\s+records?)\b"
    ),
}
NEGATED = re.compile(
    r"(?i)(?:\b(?:do\s+not|don't|never|cannot|can't|must\s+not|should\s+not|"
    r"avoid|refuse\s+to|without)|\bnot\s+to)\s+(?:\w+\s+){0,2}$"
)
OVERRIDE = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|bypass|override|replace|overwrite)\b"
    r"[^.!?;\n]{0,80}?\b(?:(?:all|any|the|your|previous|prior|earlier|above|existing|"
    r"system|developer|safety)\s+)*(?:instructions|rules|guardrails|restrictions)\b"
    r"|\b(?:you\s+are\s+now|act\s+as)\s+(?:an?\s+)?(?:unrestricted|unfiltered)\b"
)
PERSONAL_QUESTION = re.compile(r"(?i)\b(?:what\s+(?:is|are)|how\s+much(?:\s+is)?)\b")
QUESTION_PREFIX = re.compile(r"(?i)\s*(?:(?:the|your|their|his|her|[\w-]+['’]s)\s+)*")
OWNER = re.compile(
    r"(?i)\b(?:your|their|his|her|employee|customer|patient)\b|\b\w+['’]s\b"
)
RECORD_VALUE = re.compile(
    r"(?i)\s*(?:(?:for|of)\s+[^:;\n]{1,40})?\s*(?:\bis\b|:|=)\s*[$€£]?\d"
)
PROTECTION = re.compile(r"(?i)\b(?:protect|protecting|secure|securing|reset|change|safeguard|prevent)\b")
EARNINGS_QUESTION = re.compile(
    r"(?i)\bhow\s+much\s+(?:does|is)\s+[^.!?;\n]{1,48}?\s+(?:earn|paid)\b"
)
CONFIDENTIAL_PASSAGE = re.compile(
    r"(?im)(?:^\s*(?:confidential|internal\s+use\s+only|do\s+not\s+distribute|"
    r"proprietary)(?:\s+(?:document|memo|report|roadmap))?\s*[:\n-]|"
    r"\b(?:this|the)\s+(?:document|memo|report|text)\s+is\s+"
    r"(?:confidential|proprietary|internal\s+use\s+only)\b)"
)


def _negated(text: str, start: int) -> bool:
    return bool(NEGATED.search(text[max(0, start - 48):start]))


def _segments(text: str):
    """Keep offsets: punctuation ends a sentence only when followed by whitespace."""
    start = 0
    for boundary in re.finditer(r"(?<=[.!?;])\s+|\r?\n+", text):
        if text[start:boundary.start()].strip():
            yield start, boundary.start()
        start = boundary.end()
    if text[start:].strip():
        yield start, len(text)


class IntentContextClassifier(HeuristicContextClassifier):
    """Classify supported instructions and sensitive passages, not topic alone.

    Local negation applies to its action only. Quotation, a research pretext, or
    an unrelated protective sentence cannot exempt another disclosure request.
    Text-only rules cannot infer authorization or replace a semantic model.
    """

    def detect(self, text: str) -> list[Finding]:
        spans: set[tuple[str, int, int]] = set()
        # A confidentiality label protects the following paragraph, including
        # sentences containing the payload, rather than only the label itself.
        for paragraph in re.finditer(r"\S[\s\S]*?(?=\r?\n[ \t]*\r?\n|\Z)", text):
            value = paragraph.group()
            if value.strip() and CONFIDENTIAL_PASSAGE.search(value):
                spans.add(("proprietary", paragraph.start(), paragraph.end()))
        for start, end in _segments(text):
            segment = text[start:end]
            if any(not _negated(segment, match.start()) for match in OVERRIDE.finditer(segment)):
                spans.add(("prompt_injection", start, end))
            if EARNINGS_QUESTION.search(segment):
                spans.add(("retrieval", start, end))
            actions = [match for match in ACTION.finditer(segment) if not _negated(segment, match.start())]
            action_starts = [match.start() for match in actions]
            for category, pattern in TARGETS.items():
                targets = list(pattern.finditer(segment))
                if not targets:
                    continue
                # Bound evidence distance to avoid joining unrelated clauses.
                requested = any(
                    (
                        action.start() <= target.start()
                        and not PROTECTION.search(segment[action.end():target.start()])
                    ) or (
                        action.start() > target.end()
                        and re.match(r"(?i)\s+(?:it|them|that|verbatim)\b", segment[action.end():])
                    )
                    for target in targets
                    for action in actions[
                        bisect_left(action_starts, target.start() - 120):
                        bisect_right(action_starts, target.start() + 120)
                    ]
                )
                question = (
                    category in {"system_instruction", "retrieval"}
                    and OWNER.search(segment)
                    and any(
                        q.end() <= target.start()
                        and QUESTION_PREFIX.fullmatch(segment[q.end():target.start()])
                        for q in PERSONAL_QUESTION.finditer(segment) for target in targets
                    )
                    and not PROTECTION.search(segment)
                )
                record = category == "retrieval" and any(
                    RECORD_VALUE.match(segment[target.end():]) for target in targets
                )
                if requested or question or record:
                    spans.add((category, start, end))
        return [
            Finding(category, self.name, start, end, "high", 0.85)
            for category, start, end in sorted(spans, key=lambda item: (item[1], item[2], item[0]))
        ]
