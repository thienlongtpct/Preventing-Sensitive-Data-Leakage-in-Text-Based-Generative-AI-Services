import time

from privacy_gateway.audit.store import AuditStore
from privacy_gateway.detectors.pipeline import DetectorFailure, Pipeline, merge, tag
from privacy_gateway.policy.actions import apply_transforms, stronger_action
from privacy_gateway.policy.engine import PolicyEngine
from privacy_gateway.schemas import SEVERITY_WEIGHT, Finding, Request, Result
from privacy_gateway.services.agent import ToolBroker
from privacy_gateway.services.llm import SimulatedLLM
from privacy_gateway.services.rag import Retriever

SERVICES = {"chat", "rag", "agent"}


class PrivacyGateway:
    """Inspect a request, enforce policy, call the simulated service, then inspect the output."""

    def __init__(
        self,
        pipeline: Pipeline,
        policy: PolicyEngine,
        audit: AuditStore,
        llm: SimulatedLLM,
        retriever: Retriever,
        tools: ToolBroker,
        token_key: str,
        max_chars: int = 20000,
        protected: bool = True,
    ):
        self.pipeline = pipeline
        self.policy = policy
        self.audit = audit
        self.llm = llm
        self.retriever = retriever
        self.tools = tools
        self.token_key = token_key
        self.max_chars = max_chars
        self.protected = protected

    def handle(self, request: Request, protected: bool | None = None) -> Result:
        started = time.perf_counter()
        enforce = self.protected if protected is None else protected
        warnings: list[str] = []

        if request.service not in SERVICES or len(request.text) > self.max_chars:
            return self._finish(request, "block", None, [], ["Request rejected."], enforce, started)

        try:
            input_findings = tag(self.pipeline.analyze(request.text), "input")
        except DetectorFailure:
            return self._finish(
                request,
                "block",
                None,
                [],
                ["Detector unavailable. Failed closed."],
                enforce,
                started,
            )

        input_decision = self.policy.decide(request.role, input_findings)
        if input_decision.unknown_role:
            return self._finish(
                request,
                "block",
                None,
                input_findings,
                ["Unknown role. Failed closed."],
                enforce,
                started,
            )

        if enforce and input_decision.action == "block":
            warnings.extend(_warning_lines(input_decision.annotated))
            return self._finish(request, "block", None, input_findings, warnings, enforce, started)

        model_input = request.text
        if enforce:
            model_input = apply_transforms(request.text, input_decision.annotated, self.token_key)

        findings = list(input_findings)
        context_action = "allow"
        try:
            context, context_findings, context_action, context_warnings = self._context(
                request, enforce
            )
        except DetectorFailure:
            return self._finish(
                request,
                "block",
                None,
                findings,
                ["Detector unavailable. Failed closed."],
                enforce,
                started,
            )
        findings.extend(context_findings)
        warnings.extend(context_warnings)

        raw_output = self.llm.complete(model_input, context)
        try:
            output_findings = tag(self.pipeline.analyze(raw_output), "output")
        except DetectorFailure:
            return self._finish(
                request,
                "block",
                None,
                findings,
                ["Detector unavailable. Failed closed."],
                enforce,
                started,
            )
        findings.extend(output_findings)
        output_decision = self.policy.decide(request.role, output_findings)

        if not enforce:
            return self._finish(request, "allow", raw_output, findings, warnings, enforce, started)

        if output_decision.unknown_role or output_decision.action == "block":
            warnings.extend(_warning_lines(output_decision.annotated))
            return self._finish(request, "block", None, findings, warnings, enforce, started)

        output = apply_transforms(raw_output, output_decision.annotated, self.token_key)
        action = stronger_action(input_decision.action, output_decision.action)
        action = stronger_action(action, context_action)
        warnings.extend(_warning_lines(input_decision.annotated))
        warnings.extend(_warning_lines(output_decision.annotated))
        return self._finish(request, action, output, findings, _unique(warnings), enforce, started)

    def _context(self, request: Request, enforce: bool) -> tuple[str, list[Finding], str, list[str]]:
        if request.service == "rag":
            items = self.retriever.retrieve(request.text)
        elif request.service == "agent":
            items = self.tools.run(request.text)
        else:
            return "", [], "allow", []

        parts: list[str] = []
        findings: list[Finding] = []
        warnings: list[str] = []
        action = "allow"
        for item in items:
            item_findings = tag(self.pipeline.analyze(item["text"]), "context")
            if item.get("sensitivity") == "restricted":
                item_findings.append(
                    Finding(
                        category="retrieval",
                        detector="access_policy",
                        start=0,
                        end=len(item["text"]),
                        severity="high",
                        confidence=0.95,
                        source="context",
                    )
                )
                item_findings = merge(item_findings)
            findings.extend(item_findings)
            decision = self.policy.decide(request.role, item_findings)
            if decision.unknown_role:
                return "", findings, "block", ["Unknown role. Failed closed."]
            if not enforce:
                parts.append(item["text"])
                continue
            if decision.action == "block":
                warnings.append(f"Removed restricted context {item['id']}.")
                action = stronger_action(action, "redact")
                continue
            parts.append(apply_transforms(item["text"], decision.annotated, self.token_key))
            action = stronger_action(action, decision.action)
            warnings.extend(_warning_lines(decision.annotated))
        return "\n".join(parts), findings, action, warnings

    def _finish(
        self,
        request: Request,
        action: str,
        output: str | None,
        findings: list[Finding],
        warnings: list[str],
        protected: bool,
        started: float,
    ) -> Result:
        latency_ms = (time.perf_counter() - started) * 1000
        categories = sorted({finding.category for finding in findings})
        risk = max((SEVERITY_WEIGHT[finding.severity] for finding in findings), default=0.0)
        audit_id = self.audit.append(
            {
                "role": request.role.lower(),
                "service": request.service,
                "action": action,
                "categories": categories,
                "finding_count": len(findings),
                "latency_ms": round(latency_ms, 3),
                "protected": protected,
                "risk_score": risk,
                "warnings": _unique(warnings),
            }
        )
        return Result(
            action=action,
            output=output,
            findings=findings,
            warnings=_unique(warnings),
            audit_id=audit_id,
            latency_ms=latency_ms,
            protected=protected,
            risk_score=risk,
            role=request.role.lower(),
            service=request.service,
        )


def _warning_lines(annotated: list[tuple[Finding, str]]) -> list[str]:
    lines: list[str] = []
    for finding, action in annotated:
        if action == "warn":
            lines.append(f"{finding.category} detected ({finding.severity}).")
    return lines


def _unique(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen
