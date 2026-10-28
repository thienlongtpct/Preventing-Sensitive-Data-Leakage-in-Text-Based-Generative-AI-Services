import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from privacy_gateway.audit.sanitize import sanitize_event


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
    "seq",
    "prev_hash",
    "hash",
}

GENESIS = "0" * 64
KEY_ENV = "PRIVGUARD_AUDIT_KEY"


@dataclass(frozen=True)
class ChainCheck:
    ok: bool
    events: int
    keyed: bool
    first_bad: int | None = None
    reason: str = ""
    head: tuple[int, str] | None = None


class AuditStore:
    """Append-only log of sanitized events. Raw prompts and secrets are not fields.

    Each line carries a sequence number and a link to the previous line's hash, so
    an edited, dropped, inserted, or reordered event fails `verify`. Without a key
    the link is SHA-256, which catches accidental edits but can be recomputed by
    anyone who can write the file. With `key` or PRIVGUARD_AUDIT_KEY set, the link
    is HMAC-SHA256 and cannot be rebuilt without the key. Dropping events from the
    end is only caught against an anchor (`head()`) kept somewhere else.
    """

    def __init__(self, path: Path, key: bytes | str | None = None):
        self.path = path
        key = key if key is not None else os.environ.get(KEY_ENV)
        self._key = key.encode("utf-8") if isinstance(key, str) else key

    @property
    def keyed(self) -> bool:
        return self._key is not None

    def append(self, event: dict) -> str:
        safe = sanitize_event(event)
        safe.setdefault("id", str(uuid4()))
        seq, prev_hash = self.head() or (0, GENESIS)
        safe["seq"] = seq + 1
        safe["prev_hash"] = prev_hash
        safe["hash"] = self._digest(safe)
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

    def head(self) -> tuple[int, str] | None:
        """Sequence number and hash of the last event. Store it elsewhere as an anchor."""
        line = _last_line(self.path)
        if line is None:
            return None
        event = json.loads(line)
        return int(event.get("seq", 0)), str(event.get("hash", GENESIS))

    def verify(self, anchor: tuple[int, str] | None = None) -> ChainCheck:
        prev_hash = GENESIS
        count = 0
        lines = self.path.read_text(encoding="utf-8").splitlines() if self.path.exists() else []
        for line in lines:
            if not line.strip():
                continue
            count += 1
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                return self._failed(count, count, "line is not valid JSON")
            if "hash" not in event:
                return self._failed(count, count, "event has no chain fields")
            if event.get("seq") != count:
                return self._failed(count, count, "sequence number out of order")
            if event.get("prev_hash") != prev_hash:
                return self._failed(count, count, "link to the previous event is broken")
            if not hmac.compare_digest(str(event["hash"]), self._digest(event)):
                return self._failed(count, count, "event contents changed, or wrong key")
            prev_hash = event["hash"]

        head = (count, prev_hash) if count else None
        if anchor is not None:
            seq, digest = anchor
            if count < seq:
                return self._failed(count + 1, count, f"log ends before anchored event {seq}")
            if seq > 0 and _hash_at(lines, seq) != digest:
                return self._failed(seq, count, "anchored event does not match")
        return ChainCheck(ok=True, events=count, keyed=self.keyed, head=head)

    def _failed(self, position: int, events: int, reason: str) -> ChainCheck:
        return ChainCheck(ok=False, events=events, keyed=self.keyed, first_bad=position, reason=reason)

    def _digest(self, event: dict) -> str:
        return event_digest(event, self._key)


def event_digest(event: dict, key: bytes | None = None) -> str:
    """SHA-256, or HMAC-SHA256 with a key, over every field except `hash`."""
    body = {name: value for name, value in event.items() if name != "hash"}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if key is None:
        return hashlib.sha256(payload).hexdigest()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _hash_at(lines: list[str], seq: int) -> str | None:
    for line in lines:
        if line.strip():
            event = json.loads(line)
            if event.get("seq") == seq:
                return event.get("hash")
    return None


def _last_line(path: Path) -> str | None:
    """Read the final non-empty line without loading the whole log."""
    if not path.exists():
        return None
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        position = handle.tell()
        data = b""
        while position > 0:
            step = min(4096, position)
            position -= step
            handle.seek(position)
            data = handle.read(step) + data
            stripped = data.rstrip()
            if b"\n" in stripped or position == 0:
                line = stripped.rsplit(b"\n", 1)[-1].strip()
                return line.decode("utf-8") or None
    return None
