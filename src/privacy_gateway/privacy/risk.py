from dataclasses import dataclass
from functools import cached_property

from privacy_gateway.schemas import ACTION_RANK, CATEGORY_PRIORITY

ACTIONS = tuple(ACTION_RANK)
CATEGORIES = tuple(CATEGORY_PRIORITY)
ROLES = ("guest", "employee", "analyst", "admin")
SERVICES = ("chat", "rag", "agent")
HIGH_RISK = 0.75
DEFAULT_MAX_CATEGORIES = 3


@dataclass(frozen=True)
class RiskLayout:
    """Fixed slot order for what one audit event adds to the aggregate.

    Every gateway encodes events the same way, so encrypted vectors add slot by
    slot. Group keys come from this fixed list, never from the data, so an empty
    group still shows up and its absence leaks nothing. Unknown keys go to "other".
    """

    roles: tuple[str, ...] = ROLES
    services: tuple[str, ...] = SERVICES
    max_categories: int = DEFAULT_MAX_CATEGORIES

    def __post_init__(self) -> None:
        if not 1 <= self.max_categories <= len(CATEGORIES):
            raise ValueError(f"max_categories must be between 1 and {len(CATEGORIES)}")

    @classmethod
    def from_config(cls, config: dict, max_categories: int = DEFAULT_MAX_CATEGORIES) -> "RiskLayout":
        roles = tuple(name.lower() for name in config.get("roles", {})) or ROLES
        return cls(roles=roles, max_categories=max_categories)

    @property
    def role_keys(self) -> tuple[str, ...]:
        return self.roles + ("other",)

    @property
    def service_keys(self) -> tuple[str, ...]:
        return self.services + ("other",)

    @cached_property
    def statistics(self) -> dict[str, tuple[list[str], float]]:
        """Statistic name -> (slots, L1 sensitivity when one event is added or removed)."""
        return {
            "events": (["count"], 1.0),
            "risk_sum": (["risk_sum"], 1.0),
            "high_risk": (["high_risk"], 1.0),
            "actions": ([f"action:{name}" for name in ACTIONS], 1.0),
            "categories": ([f"category:{name}" for name in CATEGORIES], float(self.max_categories)),
            "by_role": (
                [f"role_count:{key}" for key in self.role_keys]
                + [f"role_risk:{key}" for key in self.role_keys],
                2.0,
            ),
            "by_service": (
                [f"service_count:{key}" for key in self.service_keys]
                + [f"service_risk:{key}" for key in self.service_keys],
                2.0,
            ),
        }

    @cached_property
    def slots(self) -> list[str]:
        return [slot for names, _ in self.statistics.values() for slot in names]

    @cached_property
    def index(self) -> dict[str, int]:
        return {slot: position for position, slot in enumerate(self.slots)}

    def encode(self, event: dict) -> list[float]:
        vector = [0.0] * len(self.slots)
        risk = min(1.0, max(0.0, float(event.get("risk_score", 0.0))))
        role = event.get("role") if event.get("role") in self.roles else "other"
        service = event.get("service") if event.get("service") in self.services else "other"
        vector[self.index["count"]] = 1.0
        vector[self.index["risk_sum"]] = risk
        vector[self.index["high_risk"]] = 1.0 if risk >= HIGH_RISK else 0.0
        if event.get("action") in ACTIONS:
            vector[self.index[f"action:{event['action']}"]] = 1.0
        for category in self.capped_categories(event):
            vector[self.index[f"category:{category}"]] = 1.0
        vector[self.index[f"role_count:{role}"]] = 1.0
        vector[self.index[f"role_risk:{role}"]] = risk
        vector[self.index[f"service_count:{service}"]] = 1.0
        vector[self.index[f"service_risk:{service}"]] = risk
        return vector

    def capped_categories(self, event: dict) -> list[str]:
        """Keep at most `max_categories`, most severe first, which bounds the sensitivity."""
        present = {name for name in event.get("categories", []) if name in CATEGORIES}
        return [name for name in CATEGORIES if name in present][: self.max_categories]

    def total(self, events: list[dict]) -> list[float]:
        totals = [0.0] * len(self.slots)
        for event in events:
            for position, value in enumerate(self.encode(event)):
                totals[position] += value
        return totals

    def decode(self, vector: list[float]) -> dict[str, float]:
        return dict(zip(self.slots, vector))


def summarize(totals: dict[str, float], layout: RiskLayout) -> dict:
    """Turn slot totals, exact or noisy, into risk metrics. Works on any subset of statistics."""
    summary: dict = {}
    events = totals.get("count")
    denominator = max(events, 1.0) if events is not None else None
    if events is not None:
        summary["events"] = round(events)
    if "risk_sum" in totals:
        summary["risk_sum"] = round(totals["risk_sum"], 2)
        if denominator:
            summary["mean_risk"] = _rate(totals["risk_sum"], denominator)
    if "high_risk" in totals and denominator:
        summary["high_risk_rate"] = _rate(totals["high_risk"], denominator)
    if "action:block" in totals:
        summary["actions"] = {name: round(totals[f"action:{name}"]) for name in ACTIONS}
        if denominator:
            summary["block_rate"] = _rate(totals["action:block"], denominator)
    if f"category:{CATEGORIES[0]}" in totals:
        summary["categories"] = {name: round(totals[f"category:{name}"]) for name in CATEGORIES}
    for group, prefix, keys in (
        ("by_role", "role", layout.role_keys),
        ("by_service", "service", layout.service_keys),
    ):
        if f"{prefix}_count:{keys[0]}" in totals:
            summary[group] = {}
            for key in keys:
                count = totals[f"{prefix}_count:{key}"]
                summary[group][key] = {
                    "events": round(count),
                    "mean_risk": _rate(totals[f"{prefix}_risk:{key}"], max(count, 1.0)),
                }
    return summary


def split_batches(items: list, parties: int) -> list[list]:
    """Deal items round-robin to `parties` gateways. Empty batches are dropped."""
    if parties < 1:
        raise ValueError("parties must be at least 1")
    batches: list[list] = [[] for _ in range(parties)]
    for position, item in enumerate(items):
        batches[position % parties].append(item)
    return [batch for batch in batches if batch]


def _rate(numerator: float, denominator: float) -> float:
    return round(min(1.0, max(0.0, numerator / denominator)), 4)
