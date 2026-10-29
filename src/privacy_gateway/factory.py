import json
import os
from pathlib import Path

import yaml

from privacy_gateway.audit.store import AuditStore
from privacy_gateway.detectors.context import HeuristicContextClassifier
from privacy_gateway.detectors.entropy import EntropyDetector
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
) -> PrivacyGateway:
    root = root or project_root()
    config = yaml.safe_load((root / "config" / "policy.yaml").read_text(encoding="utf-8"))
    corpus = json.loads((root / "data" / "corpus.json").read_text(encoding="utf-8"))
    tools = json.loads((root / "data" / "tools.json").read_text(encoding="utf-8"))

    use_spacy = os.environ.get("PRIVGUARD_SPACY") == "1"
    detectors = [
        StructuredSecretDetector(),
        EntityDetector(),
        EntropyDetector(),
        HeuristicContextClassifier(),
        MarkerDetector(config.get("markers", {})),
        SpacyNameDetector(enabled=use_spacy),
    ]
    pipeline = Pipeline(detectors, optional={"spacy"})
    return PrivacyGateway(
        pipeline=pipeline,
        policy=PolicyEngine(config["roles"], fail_closed=bool(config.get("fail_closed", True))),
        audit=AuditStore(audit_path or (root / "var" / "audit.jsonl")),
        llm=SimulatedLLM(config["system_prompt"], config["canary"]),
        retriever=Retriever(corpus),
        tools=ToolBroker(tools),
        token_key=str(config.get("token_key", "dev-only-change-me")),
        max_chars=int(config.get("max_chars", 20000)),
        protected=protected,
    )


def load_config(root: Path | None = None) -> dict:
    root = root or project_root()
    return yaml.safe_load((root / "config" / "policy.yaml").read_text(encoding="utf-8"))
