import random

from privacy_gateway.privacy.accountant import PrivacyAccountant
from privacy_gateway.privacy.differential import error_bound, laplace_scale, noisy_counts, privacy_backend
from privacy_gateway.privacy.homomorphic import secure_sum
from privacy_gateway.privacy.risk import RiskLayout, split_batches, summarize

DEFAULT_STATISTICS = ("events", "risk_sum", "high_risk", "actions", "categories", "by_role", "by_service")


def build_privacy_report(
    events: list[dict],
    epsilon: float,
    seed: int | None = None,
    parties: int = 3,
    layout: RiskLayout | None = None,
) -> dict:
    """Report for the local evaluation harness.

    `events` and `homomorphic_risk` are exact and must stay with the auditor.
    `differential_privacy` is the noisy release. Anything that leaves the auditor
    should come from `publish_report`, which also charges a privacy budget.
    """
    layout = layout or RiskLayout()
    totals, aggregation = aggregate_events(split_batches(events, parties), layout)
    noisy, noise = release(totals, layout, epsilon, seed=seed)
    published = summarize(noisy, layout)
    risk_sum = totals["risk_sum"]
    count = round(totals["count"])
    return {
        "events": len(events),
        "epsilon": epsilon,
        "differential_privacy": {
            "backend": privacy_backend(),
            "composition": "sequential",
            "unit": "one audit event",
            "max_categories_per_event": layout.max_categories,
            "actions": published.get("actions", {}),
            "categories": published.get("categories", {}),
            "risk": published,
            "noise": noise,
        },
        "homomorphic_risk": {
            "sum": risk_sum,
            "count": count,
            "mean": risk_sum / count if count else 0.0,
            **aggregation,
        },
    }


def publish_report(
    batches: list[list[dict]],
    epsilon: float,
    accountant: PrivacyAccountant | None = None,
    statistics: tuple[str, ...] = DEFAULT_STATISTICS,
    layout: RiskLayout | None = None,
    seed: int | None = None,
    encrypted: bool = True,
    label: str = "audit report",
) -> dict:
    """The release that may leave the auditor: noisy risk metrics and their error bars.

    Each batch is one gateway's sanitized events. The budget is checked before
    anything is computed and charged only once the release is built.
    """
    layout = layout or RiskLayout()
    if accountant is not None:
        accountant.check(epsilon)
    totals, aggregation = aggregate_events(batches, layout, encrypted=encrypted)
    noisy, noise = release(totals, layout, epsilon, statistics, seed=seed)
    report = {
        "epsilon": epsilon,
        "dp_backend": privacy_backend(),
        "aggregation": {"backend": aggregation["backend"], "parties": aggregation["parties"]},
        "unit": "one audit event",
        "max_categories_per_event": layout.max_categories,
        "noise": noise,
        "risk": summarize(noisy, layout),
    }
    report["warnings"] = signal_warnings(report["risk"], noise)
    if accountant is not None:
        accountant.spend(epsilon, label)
        report["budget"] = accountant.summary()
    return report


def signal_warnings(risk: dict, noise: list[dict], ratio: float = 0.1) -> list[str]:
    """Flag a release whose noise is large next to the published event count."""
    bar = max(row["error95"] for row in noise)
    events = risk.get("events")
    if events is None or bar <= ratio * max(events, 1):
        return []
    return [
        f"Counts carry up to ±{bar:g} noise against about {events} events, so rates and small "
        "groups are unreliable. Report over more events, raise epsilon, or publish fewer statistics."
    ]


def aggregate_events(
    batches: list[list[dict]], layout: RiskLayout, encrypted: bool = True
) -> tuple[dict[str, float], dict]:
    """Encode each gateway's events, add them under encryption, and return exact slot totals."""
    vectors = [layout.total(batch) for batch in batches if batch]
    if not vectors:
        return layout.decode([0.0] * len(layout.slots)), {"backend": "none", "parties": 0}
    result = secure_sum(vectors, encrypted=encrypted)
    totals = [round(value, 6) for value in result.totals]
    return layout.decode(totals), result.info()


def release(
    totals: dict[str, float],
    layout: RiskLayout,
    epsilon: float,
    statistics: tuple[str, ...] = DEFAULT_STATISTICS,
    seed: int | None = None,
    weights: dict[str, float] | None = None,
) -> tuple[dict[str, float], list[dict]]:
    """Add Laplace noise per statistic, splitting `epsilon` across them.

    The epsilons add up to `epsilon` (sequential composition). Each histogram is
    one statistic because an event's L1 effect on it is bounded by its
    sensitivity. Default weights follow sensitivity, so every slot gets the
    same noise scale.
    """
    allocation = allocate_budget(layout, epsilon, statistics, weights)
    seeds = _seeds(seed, len(statistics))
    noisy: dict[str, float] = {}
    noise: list[dict] = []
    for name, stat_seed in zip(statistics, seeds):
        slots, sensitivity = layout.statistics[name]
        share = allocation[name]
        noisy.update(
            noisy_counts({slot: totals[slot] for slot in slots}, share, seed=stat_seed, sensitivity=sensitivity)
        )
        scale = laplace_scale(sensitivity, share)
        noise.append(
            {
                "statistic": name,
                "epsilon": round(share, 6),
                "sensitivity": sensitivity,
                "noise_scale": round(scale, 4),
                "error95": round(error_bound(scale), 3),
            }
        )
    return noisy, noise


def allocate_budget(
    layout: RiskLayout,
    epsilon: float,
    statistics: tuple[str, ...],
    weights: dict[str, float] | None = None,
) -> dict[str, float]:
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    if not statistics:
        raise ValueError("choose at least one statistic")
    unknown = set(statistics) - set(layout.statistics)
    if unknown:
        raise ValueError(f"unknown statistics: {', '.join(sorted(unknown))}")
    weights = weights or {name: layout.statistics[name][1] for name in statistics}
    total = sum(weights[name] for name in statistics)
    return {name: epsilon * weights[name] / total for name in statistics}


def _seeds(seed: int | None, count: int) -> list[int | None]:
    """Give each statistic its own stream, so no two share a noise draw."""
    if seed is None:
        return [None] * count
    rng = random.Random(seed)
    return [rng.getrandbits(32) for _ in range(count)]
