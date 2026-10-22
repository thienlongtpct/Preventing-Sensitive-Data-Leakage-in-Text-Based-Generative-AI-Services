import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


AUDIT_FIELDS = {
    "id",
    "ts",
    "role",
    "service",
    "action",
    "categories",
    "finding_count",
    "latency_ms",
    "protected",
    "risk_score",
    "warnings",
}


class AuditStore:
    """Append-only log of sanitized events. Raw prompts and secrets are not fields."""

    def __init__(self, path: Path):
        self.path = path

    def append(self, event: dict) -> str:
        safe = {key: event[key] for key in AUDIT_FIELDS if key in event}
        safe["id"] = str(safe.get("id") or uuid4())
        safe.setdefault("ts", datetime.now(timezone.utc).isoformat())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(safe, sort_keys=True) + "\n")
        return safe["id"]

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        events: list[dict] = []
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events
