from dataclasses import replace

from privacy_gateway.policy.engine import prefer_category
from privacy_gateway.schemas import Finding, SEVERITY_WEIGHT


class DetectorFailure(RuntimeError):
    """A required detector could not produce a result."""


class Pipeline:
    def __init__(self, detectors: list, optional: set[str] | None = None):
        self.detectors = detectors
        self.optional = optional or set()

    def analyze(self, text: str) -> list[Finding]:
        if not text:
            return []
        found: list[Finding] = []
        for detector in self.detectors:
            try:
                found.extend(detector.detect(text))
            except Exception as exc:
                if getattr(detector, "name", "") in self.optional:
                    continue
                name = getattr(detector, "name", detector.__class__.__name__)
                raise DetectorFailure(name) from exc
        return merge(found)


def merge(findings: list[Finding]) -> list[Finding]:
    if not findings:
        return []
    ordered = sorted(findings, key=lambda finding: (finding.start, -(finding.end - finding.start)))
    merged: list[Finding] = [ordered[0]]
    for finding in ordered[1:]:
        last = merged[-1]
        if finding.start <= last.end:
            merged[-1] = _combine(last, finding)
        else:
            merged.append(finding)
    return merged


def _combine(left: Finding, right: Finding) -> Finding:
    severity = left.severity if SEVERITY_WEIGHT[left.severity] >= SEVERITY_WEIGHT[right.severity] else right.severity
    detectors = sorted({left.detector, right.detector})
    return Finding(
        category=prefer_category(left.category, right.category),
        detector="+".join(detectors),
        start=min(left.start, right.start),
        end=max(left.end, right.end),
        severity=severity,
        confidence=max(left.confidence, right.confidence),
        source=left.source,
    )


def tag(findings: list[Finding], source: str) -> list[Finding]:
    return [replace(finding, source=source) for finding in findings]
