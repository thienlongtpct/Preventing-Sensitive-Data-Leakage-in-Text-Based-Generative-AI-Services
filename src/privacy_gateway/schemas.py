from dataclasses import dataclass, field


SEVERITY_WEIGHT = {
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}

ACTION_RANK = {
    "allow": 0,
    "warn": 1,
    "redact": 2,
    "tokenize": 3,
    "block": 4,
}

CATEGORY_PRIORITY = [
    "secret",
    "system_instruction",
    "memorized",
    "prompt_injection",
    "retrieval",
    "proprietary",
    "pii",
]


@dataclass(frozen=True)
class Finding:
    category: str
    detector: str
    start: int
    end: int
    severity: str
    confidence: float
    source: str = "input"

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHT:
            raise ValueError(f"Unknown severity: {self.severity}")
        if self.category not in CATEGORY_PRIORITY:
            raise ValueError(f"Unknown category: {self.category}")
        if self.start < 0 or self.end < self.start:
            raise ValueError("Invalid finding span")


@dataclass(frozen=True)
class Request:
    text: str
    role: str
    service: str = "chat"


@dataclass
class Decision:
    action: str
    annotated: list[tuple[Finding, str]] = field(default_factory=list)
    unknown_role: bool = False


@dataclass
class Result:
    action: str
    output: str | None
    findings: list[Finding]
    warnings: list[str]
    audit_id: str
    latency_ms: float
    protected: bool
    risk_score: float
    role: str
    service: str

    @property
    def sensitive(self) -> bool:
        return bool(self.findings)
