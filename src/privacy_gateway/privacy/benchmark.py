"""Privacy-utility and overhead measurements for the audit and risk-aggregation pipeline."""

import json
import random
import statistics
from pathlib import Path

from privacy_gateway.privacy.differential import privacy_backend
from privacy_gateway.privacy.homomorphic import he_backend, secure_sum
from privacy_gateway.privacy.reporting import release
from privacy_gateway.privacy.risk import CATEGORIES, RiskLayout, split_batches
from privacy_gateway.schemas import ACTION_RANK, SEVERITY_WEIGHT

EPSILONS = (0.1, 0.25, 0.5, 1.0, 2.0, 5.0)
SIZES = (500, 5000, 50000)
CAPS = (1, 2, 3, 4, 5, 7)
PARTIES = (1, 2, 4, 8, 16, 32)

ROLE_WEIGHTS = {"guest": 0.3, "employee": 0.4, "analyst": 0.2, "admin": 0.1}
SERVICE_WEIGHTS = {"chat": 0.5, "rag": 0.3, "agent": 0.2}
FINDING_COUNTS = {0: 0.5, 1: 0.3, 2: 0.12, 3: 0.05, 4: 0.03}
CATEGORY_SEVERITY = {
    "secret": "critical",
    "system_instruction": "high",
    "memorized": "high",
    "prompt_injection": "high",
    "retrieval": "high",
    "proprietary": "medium",
    "pii": "medium",
}

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
GRID = "#e4e3de"
SERIES = ("#2a78d6", "#eb6834", "#1baf7a")


def synthetic_events(count: int, roles: dict[str, dict[str, str]], seed: int = 0) -> list[dict]:
    """Sanitized-looking audit events whose action follows the real role policy."""
    rng = random.Random(seed)
    events: list[dict] = []
    for _ in range(count):
        role = _pick(rng, ROLE_WEIGHTS)
        service = _pick(rng, SERVICE_WEIGHTS)
        categories = rng.sample(CATEGORIES, _pick(rng, FINDING_COUNTS))
        severities = [CATEGORY_SEVERITY[name] for name in categories]
        if "pii" in categories and rng.random() < 0.5:
            severities[categories.index("pii")] = "low"
        actions = [roles[role][severity] for severity in severities] or ["allow"]
        events.append(
            {
                "role": role,
                "service": service,
                "action": max(actions, key=ACTION_RANK.get),
                "categories": sorted(categories),
                "risk_score": max((SEVERITY_WEIGHT[s] for s in severities), default=0.0),
            }
        )
    return events


def run_benchmark(roles: dict[str, dict[str, str]], trials: int = 200, seed: int = 0) -> dict:
    return {
        "dp_backend": privacy_backend(),
        "he_backend": he_backend(),
        "trials": trials,
        "epsilon_sweep": epsilon_sweep(roles, trials, seed),
        "category_cap": category_cap_sweep(roles, trials, seed),
        "homomorphic": parties_sweep(roles, seed),
    }


def epsilon_sweep(roles: dict, trials: int, seed: int) -> list[dict]:
    layout = RiskLayout(roles=tuple(roles))
    rows: list[dict] = []
    for size in SIZES:
        totals = layout.decode(layout.total(synthetic_events(size, roles, seed)))
        exact = _metrics(totals)
        for epsilon in EPSILONS:
            mean_risk, block_rate, categories = [], [], []
            for trial in range(trials):
                noisy, _ = release(totals, layout, epsilon, seed=seed * 100003 + trial)
                published = _metrics(noisy)
                mean_risk.append(abs(published["mean_risk"] - exact["mean_risk"]))
                block_rate.append(abs(published["block_rate"] - exact["block_rate"]))
                categories.append(_relative_l1(published["categories"], exact["categories"]))
            rows.append(
                {
                    "events": size,
                    "epsilon": epsilon,
                    "mean_risk_abs_error": statistics.fmean(mean_risk),
                    "block_rate_abs_error": statistics.fmean(block_rate),
                    "category_relative_error": statistics.fmean(categories),
                }
            )
    return rows


def category_cap_sweep(roles: dict, trials: int, seed: int, epsilon: float = 1.0) -> list[dict]:
    """Smaller caps mean less noise but drop categories from multi-finding events."""
    rows: list[dict] = []
    for size in SIZES[1:]:
        events = synthetic_events(size, roles, seed)
        truth = {name: sum(name in event["categories"] for event in events) for name in CATEGORIES}
        for cap in CAPS:
            layout = RiskLayout(roles=tuple(roles), max_categories=cap)
            totals = layout.decode(layout.total(events))
            errors = []
            for trial in range(trials):
                noisy, _ = release(totals, layout, epsilon, seed=seed * 100003 + trial)
                errors.append(_relative_l1(_metrics(noisy)["categories"], truth))
            truncated = sum(len(event["categories"]) > cap for event in events)
            rows.append(
                {
                    "events": size,
                    "max_categories": cap,
                    "epsilon": epsilon,
                    "category_relative_error": statistics.fmean(errors),
                    "truncated_events": truncated,
                }
            )
    return rows


def parties_sweep(roles: dict, seed: int, events: int = 5000, repeats: int = 3) -> list[dict]:
    layout = RiskLayout(roles=tuple(roles))
    population = synthetic_events(events, roles, seed)
    rows: list[dict] = []
    for parties in PARTIES:
        vectors = [layout.total(batch) for batch in split_batches(population, parties)]
        plain = [sum(values) for values in zip(*vectors)]
        runs = [secure_sum(vectors) for _ in range(repeats)]
        error = max(abs(a - b) for a, b in zip(runs[0].totals, plain))
        timing = {
            step: statistics.median(run.timings_ms[step] for run in runs)
            for step in ("keygen", "encrypt", "aggregate", "decrypt")
        }
        rows.append(
            {
                "parties": parties,
                "events": events,
                "slots": len(layout.slots),
                "public_context_bytes": runs[0].public_context_bytes,
                "ciphertext_bytes": runs[0].ciphertext_bytes,
                "bytes_to_aggregator": runs[0].ciphertext_bytes * parties,
                "max_abs_error": error,
                **{f"{step}_ms": value for step, value in timing.items()},
            }
        )
    return rows


def write_outputs(results: dict, out_dir: Path, charts: bool = True) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = [out_dir / "results.json", out_dir / "summary.md"]
    written[0].write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    written[1].write_text(format_summary(results), encoding="utf-8")
    if charts:
        written.extend(_charts(results, out_dir))
    return written


def format_summary(results: dict) -> str:
    lines = [
        "# Privacy audit benchmark",
        "",
        f"DP backend `{results['dp_backend']}`, HE backend `{results['he_backend']}`, "
        f"{results['trials']} trials per point. Errors are means of absolute error.",
        "",
        "## Error vs epsilon",
        "",
        "| events | epsilon | mean risk error | block rate error | category error |",
        "| ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in results["epsilon_sweep"]:
        lines.append(
            f"| {row['events']} | {row['epsilon']} | {row['mean_risk_abs_error']:.4f} | "
            f"{row['block_rate_abs_error']:.4f} | {row['category_relative_error']:.1%} |"
        )
    lines += [
        "",
        "## Category cap at epsilon 1",
        "",
        "| events | cap | category error | events truncated |",
        "| ---: | ---: | ---: | ---: |",
    ]
    for row in results["category_cap"]:
        lines.append(
            f"| {row['events']} | {row['max_categories']} | {row['category_relative_error']:.1%} | "
            f"{row['truncated_events']} |"
        )
    lines += [
        "",
        "## Encrypted aggregation by number of gateways",
        "",
        "| gateways | keygen ms | encrypt ms (all) | aggregate ms | decrypt ms | "
        "ciphertext KB | to aggregator KB | max error |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in results["homomorphic"]:
        lines.append(
            f"| {row['parties']} | {row['keygen_ms']:.1f} | {row['encrypt_ms']:.1f} | "
            f"{row['aggregate_ms']:.1f} | {row['decrypt_ms']:.1f} | "
            f"{row['ciphertext_bytes'] / 1024:.0f} | {row['bytes_to_aggregator'] / 1024:.0f} | "
            f"{row['max_abs_error']:.1e} |"
        )
    return "\n".join(lines) + "\n"


def _charts(results: dict, out_dir: Path) -> list[Path]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return []

    paths: list[Path] = []

    sweep = results["epsilon_sweep"]
    fig, ax = _axes(plt, "Block-rate error vs privacy budget", "epsilon per report", "mean absolute error (points)")
    for color, size in zip(SERIES, SIZES):
        rows = [row for row in sweep if row["events"] == size]
        xs = [row["epsilon"] for row in rows]
        ys = [row["block_rate_abs_error"] * 100 for row in rows]
        _line(ax, xs, ys, color, f"{size:,} events")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks(EPSILONS, [f"{value:g}" for value in EPSILONS])
    paths.append(_save(plt, fig, ax, out_dir / "dp_error_vs_epsilon.png"))

    caps = results["category_cap"]
    fig, ax = _axes(plt, "Category-count error vs per-event cap (epsilon 1)", "categories kept per event", "relative error (%)")
    for color, size in zip(SERIES, SIZES[1:]):
        rows = [row for row in caps if row["events"] == size]
        _line(ax, [row["max_categories"] for row in rows], [row["category_relative_error"] * 100 for row in rows], color, f"{size:,} events")
    ax.set_xticks(CAPS)
    paths.append(_save(plt, fig, ax, out_dir / "category_cap_tradeoff.png"))

    he = results["homomorphic"]
    fig, ax = _axes(plt, "Encrypted aggregation time vs gateways (log-log)", "gateways (one ciphertext each)", "time (ms)")
    xs = [row["parties"] for row in he]
    for color, (step, label) in zip(SERIES, (("encrypt_ms", "encrypt, all gateways"), ("aggregate_ms", "aggregate"), ("decrypt_ms", "decrypt"))):
        _line(ax, xs, [row[step] for row in he], color, label)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks(PARTIES, [str(value) for value in PARTIES])
    paths.append(_save(plt, fig, ax, out_dir / "he_time_vs_gateways.png"))
    return paths


def _axes(plt, title: str, xlabel: str, ylabel: str):
    fig, ax = plt.subplots(figsize=(7.2, 4.2), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    ax.set_title(title, loc="left", color=INK, fontsize=12, pad=12)
    ax.set_xlabel(xlabel, color=INK_SECONDARY, fontsize=10)
    ax.set_ylabel(ylabel, color=INK_SECONDARY, fontsize=10)
    ax.grid(True, which="major", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK_SECONDARY, labelsize=9, which="both")
    return fig, ax


def _line(ax, xs, ys, color: str, label: str) -> None:
    ax.plot(xs, ys, color=color, linewidth=2, marker="o", markersize=6, markeredgecolor=SURFACE, markeredgewidth=1.5, label=label)


def _save(plt, fig, ax, path: Path) -> Path:
    legend = ax.legend(frameon=False, fontsize=9, labelcolor=INK)
    for handle in legend.legend_handles:
        handle.set_markeredgecolor(SURFACE)
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)
    return path


def _metrics(totals: dict[str, float]) -> dict:
    """Unrounded versions of the published rates, so rounding does not hide small errors."""
    events = max(totals["count"], 1.0)
    return {
        "mean_risk": min(1.0, max(0.0, totals["risk_sum"] / events)),
        "block_rate": min(1.0, max(0.0, totals["action:block"] / events)),
        "categories": {name: totals[f"category:{name}"] for name in CATEGORIES},
    }


def _relative_l1(published: dict[str, float], truth: dict[str, float]) -> float:
    total = sum(truth.values())
    return sum(abs(published[key] - truth[key]) for key in truth) / total if total else 0.0


def _pick(rng: random.Random, weights: dict):
    return rng.choices(list(weights), weights=list(weights.values()))[0]
