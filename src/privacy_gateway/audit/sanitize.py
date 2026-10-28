import re
from datetime import datetime, timezone

from privacy_gateway.schemas import ACTION_RANK, CATEGORY_PRIORITY, SEVERITY_WEIGHT

SERVICES = {"chat", "rag", "agent"}
TIMESTAMP_SECONDS = 60

_ROLE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_WARN = re.compile(r"^(\w+) detected \((\w+)\)\.$")
_FIXED_CODES = [
    ("Removed restricted context", "context_removed"),
    ("Detector unavailable", "detector_unavailable"),
    ("Unknown role", "unknown_role"),
    ("Request rejected", "request_rejected"),
]


def sanitize_event(event: dict, timestamp_seconds: int = TIMESTAMP_SECONDS) -> dict:
    """Keep only fixed-vocabulary fields, so no free text from a request reaches the log.

    Warnings become codes because gateway messages can carry record ids. The
    timestamp is floored to `timestamp_seconds` so a log line is harder to tie to
    one person's request.
    """
    role = str(event.get("role", "")).lower()
    service = str(event.get("service", ""))
    action = str(event.get("action", ""))
    safe = {
        "role": role if _ROLE.match(role) else "invalid",
        "service": service if service in SERVICES else "invalid",
        "action": action if action in ACTION_RANK else "invalid",
        "categories": sorted({c for c in event.get("categories", []) if c in CATEGORY_PRIORITY}),
        "finding_count": max(0, int(event.get("finding_count", 0))),
        "latency_ms": round(max(0.0, float(event.get("latency_ms", 0.0))), 1),
        "protected": bool(event.get("protected", True)),
        "risk_score": min(1.0, max(0.0, float(event.get("risk_score", 0.0)))),
        "warnings": sorted({warning_code(str(w)) for w in event.get("warnings", [])}),
        "ts": coarse_timestamp(event.get("ts"), timestamp_seconds),
    }
    event_id = str(event.get("id") or "")
    if _ID.match(event_id):
        safe["id"] = event_id
    return safe


def warning_code(message: str) -> str:
    match = _WARN.match(message)
    if match:
        category, severity = match.groups()
        if category in CATEGORY_PRIORITY and severity in SEVERITY_WEIGHT:
            return f"warn:{category}:{severity}"
    for prefix, code in _FIXED_CODES:
        if message.startswith(prefix):
            return code
    return "other"


def coarse_timestamp(value: str | None = None, seconds: int = TIMESTAMP_SECONDS) -> str:
    moment = datetime.now(timezone.utc)
    if value:
        try:
            moment = datetime.fromisoformat(value).astimezone(timezone.utc)
        except ValueError:
            pass
    floored = int(moment.timestamp()) // seconds * seconds
    return datetime.fromtimestamp(floored, timezone.utc).isoformat()
