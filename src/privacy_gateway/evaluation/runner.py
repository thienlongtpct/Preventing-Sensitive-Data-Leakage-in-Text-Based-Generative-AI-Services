import json
from pathlib import Path

from privacy_gateway.gateway import PrivacyGateway
from privacy_gateway.paths import project_root
from privacy_gateway.privacy.reporting import build_privacy_report
from privacy_gateway.schemas import Request
from privacy_gateway.evaluation.metrics import detection_scores


def load_cases(path: Path | None = None) -> list[dict]:
    path = path or (project_root() / "data" / "cases" / "labeled_cases.jsonl")
    cases: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def run_evaluation(gateway: PrivacyGateway, cases: list[dict], epsilon: float = 1.0) -> dict:
    before = len(gateway.audit.read_all())
    rows: list[dict] = []
    for mode, protected in (("protected", True), ("unprotected", False)):
        for case in cases:
            result = gateway.handle(
                Request(text=case["text"], role=case["role"], service=case["service"]),
                protected=protected,
            )
            output = result.output or ""
            leaks = [item for item in case.get("leak_strings", []) if item in output]
            rows.append(
                {
                    "id": case["id"],
                    "mode": mode,
                    "leakage_type": case.get("leakage_type", "none"),
                    "action": result.action,
                    "detected": result.sensitive,
                    "expect_sensitive": bool(case["expect_sensitive"]),
                    "attack_success": bool(leaks),
                    "has_attack": bool(case.get("leak_strings")),
                    "utility_ok": (
                        not case["expect_sensitive"]
                        and bool(result.output)
                        and result.action in {"allow", "warn"}
                    ),
                    "latency_ms": result.latency_ms,
                }
            )

    protected_rows = [row for row in rows if row["mode"] == "protected"]
    detection = detection_scores(
        [row["expect_sensitive"] for row in protected_rows],
        [row["detected"] for row in protected_rows],
    )
    events = gateway.audit.read_all()[before:]
    return {
        "detection": detection,
        "modes": {mode: _mode_summary(rows, mode) for mode in ("protected", "unprotected")},
        "by_leakage_type": _by_type(rows),
        "privacy": build_privacy_report(events, epsilon),
        "rows": rows,
    }


def format_report(report: dict) -> str:
    detection = report["detection"]
    lines = [
        "Detection on protected runs",
        (
            f"  precision {detection['precision']:.2f}  recall {detection['recall']:.2f}  "
            f"f1 {detection['f1']:.2f}  fpr {detection['fpr']:.2f}"
        ),
        (
            f"  tp {detection['tp']}  fp {detection['fp']}  "
            f"tn {detection['tn']}  fn {detection['fn']}"
        ),
        "",
        f"{'mode':<14}{'attack_success':>16}{'utility':>10}{'latency_ms':>12}",
    ]
    for mode, summary in report["modes"].items():
        lines.append(
            f"{mode:<14}{summary['attack_success']:>16.2f}"
            f"{summary['utility']:>10.2f}{summary['mean_latency_ms']:>12.2f}"
        )
    lines.extend(["", "Attack success by leakage type"])
    for leakage_type, modes in report["by_leakage_type"].items():
        lines.append(
            f"  {leakage_type:<22} protected {modes['protected']:.2f}   "
            f"unprotected {modes['unprotected']:.2f}"
        )
    privacy = report["privacy"]
    homo = privacy["homomorphic_risk"]
    lines.extend(
        [
            "",
            "Privacy report for this run",
            f"  events {privacy['events']}  epsilon {privacy['epsilon']}  "
            f"dp {privacy['differential_privacy']['backend']}",
            f"  encrypted risk sum ({homo['backend']}): {homo['sum']:.3f} over {homo['count']} events",
            "",
            "Cases",
        ]
    )
    for row in report["rows"]:
        lines.append(
            f"  {row['mode']:<12} {row['id']:<24} action {row['action']:<8} "
            f"detected {str(row['detected']):<5} leaked {str(row['attack_success'])}"
        )
    return "\n".join(lines)


def _mode_summary(rows: list[dict], mode: str) -> dict:
    subset = [row for row in rows if row["mode"] == mode]
    attacks = [row for row in subset if row["has_attack"]]
    benign = [row for row in subset if not row["expect_sensitive"]]
    return {
        "cases": len(subset),
        "attack_success": (sum(row["attack_success"] for row in attacks) / len(attacks)) if attacks else 0.0,
        "utility": (sum(row["utility_ok"] for row in benign) / len(benign)) if benign else 0.0,
        "mean_latency_ms": (sum(row["latency_ms"] for row in subset) / len(subset)) if subset else 0.0,
    }


def _by_type(rows: list[dict]) -> dict[str, dict[str, float]]:
    types = sorted({row["leakage_type"] for row in rows if row["has_attack"]})
    summary: dict[str, dict[str, float]] = {}
    for leakage_type in types:
        summary[leakage_type] = {}
        for mode in ("protected", "unprotected"):
            subset = [
                row
                for row in rows
                if row["mode"] == mode and row["leakage_type"] == leakage_type and row["has_attack"]
            ]
            summary[leakage_type][mode] = (
                sum(row["attack_success"] for row in subset) / len(subset) if subset else 0.0
            )
    return summary
