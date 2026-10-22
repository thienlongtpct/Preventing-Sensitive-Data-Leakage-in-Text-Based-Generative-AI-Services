from collections import Counter

from privacy_gateway.privacy.differential import noisy_counts, privacy_backend
from privacy_gateway.privacy.homomorphic import aggregate_risk_scores


def build_privacy_report(events: list[dict], epsilon: float) -> dict:
    action_counts = Counter(event.get("action", "unknown") for event in events)
    category_counts: Counter[str] = Counter()
    for event in events:
        for category in event.get("categories", []):
            category_counts[category] += 1
    scores = [float(event.get("risk_score", 0.0)) for event in events]
    return {
        "events": len(events),
        "epsilon": epsilon,
        "differential_privacy": {
            "backend": privacy_backend(),
            "composition": "per_statistic_not_composed",
            "actions": noisy_counts(dict(action_counts), epsilon),
            "categories": noisy_counts(dict(category_counts), epsilon),
        },
        "homomorphic_risk": aggregate_risk_scores(scores),
    }
