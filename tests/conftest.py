from pathlib import Path

import pytest

from privacy_gateway.factory import build_gateway

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def gateway(tmp_path):
    return build_gateway(ROOT, audit_path=tmp_path / "audit.jsonl")
