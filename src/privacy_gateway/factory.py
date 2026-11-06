"""Build a fully wired PrivacyGateway from config/policy.yaml and the synthetic data files."""

import json
import os
from pathlib import Path

import yaml

from privacy_gateway.audit.store import AuditStore
from privacy_gateway.detectors.intent_context import IntentContextClassifier
from privacy_gateway.detectors.contextual_entropy import ContextualEntropyDetector
from privacy_gateway.detectors.entities import EntityDetector, SpacyNameDetector
from privacy_gateway.detectors.markers import MarkerDetector
from privacy_gateway.detectors.pipeline import Pipeline
from privacy_gateway.detectors.structured_secrets import StructuredSecretDetector
from privacy_gateway.gateway import PrivacyGateway
from privacy_gateway.paths import project_root
from privacy_gateway.policy.engine import PolicyEngine
from privacy_gateway.services.agent import ToolBroker
from privacy_gateway.services.llm import SimulatedLLM
from privacy_gateway.services.rag import Retriever


def build_gateway(
    root: Path | None = None,
    audit_path: Path | None = None,
    protected: bool = True,
    follow_injected_instructions: bool = False,
) -> PrivacyGateway:
    """Create a gateway with the default detector stack.

    The audit log defaults to var/audit.jsonl. The spaCy name detector runs
    only when PRIVGUARD_SPACY=1, and it is optional, so its failure does not
    block requests. Set `follow_injected_instructions` to make the simulated
    model obey instructions planted in retrieved context, for injection tests.
    """
    root = root or project_root()
    config = yaml.safe_load((root / "config" / "policy.yaml").read_text(encoding="utf-8"))
    corpus = json.loads((root / "data" / "corpus.json").read_text(encoding="utf-8"))
    tools = json.loads((root / "data" / "tools.json").read_text(encoding="utf-8"))

    use_spacy = os.environ.get("PRIVGUARD_SPACY") == "1"
    detectors = [
        StructuredSecretDetector(),
        EntityDetector(),
        ContextualEntropyDetector(),
        IntentContextClassifier(),
        MarkerDetector(config.get("markers", {})),
        SpacyNameDetector(enabled=use_spacy),
    ]
    pipeline = Pipeline(detectors, optional={"spacy"})
    return PrivacyGateway(
        pipeline=pipeline,
        policy=PolicyEngine(config["roles"], fail_closed=bool(config.get("fail_closed", True))),
        audit=AuditStore(audit_path or (root / "var" / "audit.jsonl")),
        llm=SimulatedLLM(
            config["system_prompt"],
            config["canary"],
            follow_context_instructions=follow_injected_instructions,
        ),
        retriever=Retriever(corpus),
        tools=ToolBroker(tools),
        token_key=str(config.get("token_key", "dev-only-change-me")),
        max_chars=int(config.get("max_chars", 20000)),
        protected=protected,
    )


def load_config(root: Path | None = None) -> dict:
    """Load config/policy.yaml as a dict."""
    root = root or project_root()
    return yaml.safe_load((root / "config" / "policy.yaml").read_text(encoding="utf-8"))
