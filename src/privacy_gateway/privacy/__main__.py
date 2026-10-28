"""Privacy-preserving audit and risk aggregation commands.

    python -m privacy_gateway.privacy report
    python -m privacy_gateway.privacy verify
    python -m privacy_gateway.privacy budget
    python -m privacy_gateway.privacy demo
    python -m privacy_gateway.privacy benchmark
"""

import argparse
import json
import random
import shutil
import tempfile
from pathlib import Path

from privacy_gateway.audit.store import GENESIS, AuditStore, event_digest
from privacy_gateway.evaluation.runner import load_cases
from privacy_gateway.factory import build_gateway, load_config
from privacy_gateway.paths import project_root
from privacy_gateway.privacy.accountant import BudgetExceeded, PrivacyAccountant
from privacy_gateway.privacy.benchmark import run_benchmark, write_outputs
from privacy_gateway.privacy.homomorphic import Aggregator, GatewayEncryptor, KeyHolder, he_backend
from privacy_gateway.privacy.reporting import DEFAULT_STATISTICS, aggregate_events, publish_report
from privacy_gateway.privacy.risk import DEFAULT_MAX_CATEGORIES, RiskLayout, split_batches, summarize
from privacy_gateway.schemas import Request

DEFAULT_BUDGET = 3.0
DEMO_KEY = "demo-only-audit-key"
DEMO_GATEWAYS = {
    "support": {"guest": 0.7, "employee": 0.3},
    "engineering": {"employee": 0.6, "admin": 0.4},
    "analytics": {"analyst": 0.8, "employee": 0.2},
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m privacy_gateway.privacy",
        description="Privacy-preserving audit and risk aggregation for the gateway.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    report = subparsers.add_parser("report", help="Publish a differentially private risk report")
    report.add_argument("--audit", type=Path, help="Audit log (default var/audit.jsonl)")
    report.add_argument("--ledger", type=Path, help="Budget ledger (default var/privacy_ledger.json)")
    report.add_argument("--epsilon", type=float, help="Epsilon for this report (default from config)")
    report.add_argument("--budget", type=float, default=DEFAULT_BUDGET, help="Total epsilon for a new ledger")
    report.add_argument("--parties", type=int, default=3, help="Simulated gateways sharing the log")
    report.add_argument("--stats", default=",".join(DEFAULT_STATISTICS), help="Comma-separated statistics")
    report.add_argument("--max-categories", type=int, default=DEFAULT_MAX_CATEGORIES)
    report.add_argument("--plaintext-aggregation", action="store_true", help="Skip TenSEAL")
    report.add_argument("--seed", type=int, help="Repeatable noise, for testing only")
    report.add_argument("--json", action="store_true")

    verify = subparsers.add_parser("verify", help="Check the audit log hash chain")
    verify.add_argument("--audit", type=Path)
    verify.add_argument("--anchor", help="SEQ:HASH recorded earlier, to catch a cut-off tail")

    budget = subparsers.add_parser("budget", help="Show or reset the privacy budget ledger")
    budget.add_argument("--ledger", type=Path)
    budget.add_argument("--reset", action="store_true", help="Start a new budget period")
    budget.add_argument("--total", type=float, default=DEFAULT_BUDGET)

    demo = subparsers.add_parser("demo", help="Walk through audit, tampering, encryption, and DP")
    demo.add_argument("--events", type=int, default=400, help="Requests per gateway")
    demo.add_argument("--seed", type=int, default=7)

    bench = subparsers.add_parser("benchmark", help="Privacy-utility and encryption overhead")
    bench.add_argument("--out", type=Path, help="Output folder (default var/privacy_benchmark)")
    bench.add_argument("--trials", type=int, default=200)
    bench.add_argument("--no-charts", action="store_true")

    args = parser.parse_args(argv)
    handlers = {"report": _report, "verify": _verify, "budget": _budget, "demo": _demo, "benchmark": _benchmark}
    return handlers[args.command](args)


def _report(args: argparse.Namespace) -> int:
    config = load_config()
    store = AuditStore(args.audit or _var("audit.jsonl"))
    check = store.verify()
    if not check.ok:
        print(f"Audit log failed verification at event {check.first_bad}: {check.reason}. No report published.")
        return 1
    events = store.read_all()
    if not events:
        print("Audit log is empty.")
        return 1

    epsilon = args.epsilon if args.epsilon is not None else float(config.get("epsilon", 1.0))
    accountant = PrivacyAccountant(args.budget, args.ledger or _var("privacy_ledger.json"))
    layout = RiskLayout.from_config(config, max_categories=args.max_categories)
    try:
        report = publish_report(
            split_batches(events, args.parties),
            epsilon,
            accountant=accountant,
            statistics=tuple(name.strip() for name in args.stats.split(",") if name.strip()),
            layout=layout,
            seed=args.seed,
            encrypted=not args.plaintext_aggregation,
        )
    except BudgetExceeded as error:
        print(f"Refused: {error}")
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)
    return 0


def _verify(args: argparse.Namespace) -> int:
    store = AuditStore(args.audit or _var("audit.jsonl"))
    anchor = None
    if args.anchor:
        seq, _, digest = args.anchor.partition(":")
        anchor = (int(seq), digest)
    check = store.verify(anchor)
    if check.ok:
        print(f"OK: {check.events} events, {'HMAC' if check.keyed else 'SHA-256'} chain intact.")
        if check.head:
            print(f"anchor: {check.head[0]}:{check.head[1]}")
        return 0
    print(f"FAILED at event {check.first_bad}: {check.reason}")
    return 1


def _budget(args: argparse.Namespace) -> int:
    accountant = PrivacyAccountant(args.total, args.ledger or _var("privacy_ledger.json"))
    if args.reset:
        accountant.reset(args.total)
    print(json.dumps({**accountant.summary(), "ledger": accountant.spends}, indent=2))
    return 0


def _benchmark(args: argparse.Namespace) -> int:
    results = run_benchmark(load_config()["roles"], trials=args.trials)
    paths = write_outputs(results, args.out or _var("privacy_benchmark"), charts=not args.no_charts)
    print((args.out or _var("privacy_benchmark")).joinpath("summary.md").read_text(encoding="utf-8"))
    print("Wrote " + ", ".join(str(path) for path in paths))
    return 0


def _demo(args: argparse.Namespace) -> int:
    config = load_config()
    layout = RiskLayout.from_config(config)
    cases = load_cases()
    rng = random.Random(args.seed)
    with tempfile.TemporaryDirectory() as folder:
        tmp = Path(folder)
        stores: dict[str, AuditStore] = {}
        for name, mix in DEMO_GATEWAYS.items():
            gateway = build_gateway(audit_path=tmp / f"{name}.jsonl")
            gateway.audit = AuditStore(tmp / f"{name}.jsonl", key=DEMO_KEY)
            for _ in range(args.events):
                case = rng.choice(cases)
                role = rng.choices(list(mix), weights=list(mix.values()))[0]
                gateway.handle(Request(case["text"], role, case["service"]))
            stores[name] = gateway.audit

        _heading("1. Sanitized audit log")
        events = {name: store.read_all() for name, store in stores.items()}
        sample = next(event for event in events["support"] if event["categories"])
        print(json.dumps(sample, indent=2))
        logs = "".join(store.path.read_text(encoding="utf-8") for store in stores.values())
        secrets = {text for case in cases for text in case.get("leak_strings", [])}
        prompts = {case["text"] for case in cases}
        leaked = [text for text in secrets | prompts if text in logs]
        print(f"\n{sum(map(len, events.values()))} events over {len(stores)} gateways. "
              f"Prompts or labeled secrets found in the logs: {len(leaked)}.")

        _heading("2. Tamper evidence (HMAC chain)")
        for name, store in stores.items():
            check = store.verify()
            print(f"  {name:<12} {'intact' if check.ok else 'BROKEN'}  {check.events} events  anchor {check.head[0]}:{check.head[1][:12]}...")
        original = stores["support"]
        anchor = original.verify().head
        risky = next(event["seq"] - 1 for event in events["support"] if event["risk_score"] > 0)
        attacks = {
            f"lower event {risky + 1}'s risk score to 0": lambda lines: _edit(lines, risky, risk_score=0.0),
            f"delete event {risky + 1}": lambda lines: lines[:risky] + lines[risky + 1 :],
            "same edit, then rebuild the chain with plain SHA-256": lambda lines: _rechain(_edit(lines, risky, risk_score=0.0)),
            "cut off the last 10 events": lambda lines: lines[:-10],
        }
        for label, attack in attacks.items():
            copy = tmp / "tampered.jsonl"
            shutil.copy(original.path, copy)
            lines = copy.read_text(encoding="utf-8").splitlines()
            copy.write_text("\n".join(attack(lines)) + "\n", encoding="utf-8")
            tampered = AuditStore(copy, key=DEMO_KEY)
            plain = tampered.verify()
            anchored = tampered.verify(anchor)
            result = "caught" if not plain.ok else ("caught by anchor" if not anchored.ok else "MISSED")
            reason = plain.reason if not plain.ok else anchored.reason
            print(f"  {label:<58} {result:<17} {reason}")

        _heading("3. Encrypted aggregation across gateways")
        vectors = {name: layout.total(batch) for name, batch in events.items()}
        exact_vector = [sum(values) for values in zip(*vectors.values())]
        if he_backend() == KeyHolder.backend:
            auditor = KeyHolder()
            public = auditor.public_context()
            ciphertexts = {name: GatewayEncryptor(public).encrypt(vector) for name, vector in vectors.items()}
            aggregator = Aggregator(public)
            print(f"  auditor public context: {len(public) / 1024:.0f} KB, no secret key inside")
            for name, payload in ciphertexts.items():
                print(f"  {name:<12} sends one ciphertext of {len(payload) / 1024:.0f} KB ({len(layout.slots)} slots)")
            try:
                import tenseal as ts

                ts.ckks_vector_from(ts.context_from(public), ciphertexts["support"]).decrypt()
                print("  aggregator decrypted a gateway total: this should not happen")
            except ValueError:
                print("  aggregator tries to decrypt the support total: refused, it has no secret key")
            decrypted = auditor.decrypt(aggregator.add(list(ciphertexts.values())))[: len(exact_vector)]
            error = max(abs(a - b) for a, b in zip(decrypted, exact_vector))
            print(f"  auditor decrypts only the sum; largest CKKS error {error:.1e}")
        else:
            print("  TenSEAL is not installed, so this step runs the plaintext fallback.")

        _heading("4. Differentially private release with a budget")
        accountant = PrivacyAccountant(2.0, tmp / "ledger.json")
        exact = summarize(layout.decode(exact_vector), layout)
        for attempt in range(1, 4):
            try:
                report = publish_report(list(events.values()), 1.0, accountant=accountant, layout=layout, label=f"weekly report {attempt}")
            except BudgetExceeded as error:
                print(f"  release {attempt}: refused. {error}")
                continue
            print(f"  release {attempt}: epsilon 1.0, budget left {report['budget']['remaining']:g}")
            if attempt == 1:
                published = report["risk"]
                bars = {row["statistic"]: row["error95"] for row in report["noise"]}
                count = max(published["events"], 1)
                print(f"\n    {'metric':<28}{'exact (auditor only)':>22}{'published':>12}{'±95% noise':>12}")
                print(f"    {'events':<28}{exact['events']:>22}{published['events']:>12}{bars['events']:>12.1f}")
                for metric, field, key in (
                    ("mean risk", "mean_risk", "risk_sum"),
                    ("high-risk rate", "high_risk_rate", "high_risk"),
                    ("block rate", "block_rate", "actions"),
                ):
                    print(f"    {metric:<28}{exact[field]:>22}{published[field]:>12}{bars[key] / count:>12.3f}")
                for role, values in published["by_role"].items():
                    group = max(values["events"], 1)
                    if exact["by_role"][role]["events"]:
                        print(
                            f"    {'mean risk, ' + role:<28}{exact['by_role'][role]['mean_risk']:>22}"
                            f"{values['mean_risk']:>12}{bars['by_role'] / group:>12.3f}"
                        )
                print()
        print("\n  Rate bars are the count bar divided by the published count, so anyone can compute them.")
    return 0


def _print_report(report: dict) -> None:
    risk = report["risk"]
    aggregation = report["aggregation"]
    print(
        f"Private audit report: epsilon {report['epsilon']:g}, {report['dp_backend']} noise, "
        f"{aggregation['backend']} over {aggregation['parties']} gateways"
    )
    if "budget" in report:
        budget = report["budget"]
        print(f"Budget: spent {budget['spent']:g} of {budget['total_epsilon']:g}, {budget['remaining']:g} left")
    for warning in report.get("warnings", []):
        print(f"Warning: {warning}")
    print()
    for key in ("events", "mean_risk", "high_risk_rate", "block_rate"):
        if key in risk:
            print(f"  {key:<16}{risk[key]}")
    for key in ("actions", "categories"):
        if key in risk:
            print(f"  {key:<16}" + "  ".join(f"{name} {value}" for name, value in risk[key].items()))
    for key in ("by_role", "by_service"):
        if key in risk:
            print(f"  {key}")
            for name, values in risk[key].items():
                print(f"    {name:<12} events {values['events']:<8} mean risk {values['mean_risk']}")
    print("\n  statistic     epsilon  sensitivity  noise scale  ±95%")
    for row in report["noise"]:
        print(
            f"  {row['statistic']:<13} {row['epsilon']:<8.4g} {row['sensitivity']:<12g} "
            f"{row['noise_scale']:<12g} {row['error95']}"
        )


def _edit(lines: list[str], position: int, **changes) -> list[str]:
    event = json.loads(lines[position])
    event.update(changes)
    return lines[:position] + [json.dumps(event, sort_keys=True)] + lines[position + 1 :]


def _rechain(lines: list[str]) -> list[str]:
    """What an attacker without the HMAC key can do: recompute every link with SHA-256."""
    prev_hash = GENESIS
    rebuilt = []
    for line in lines:
        event = json.loads(line)
        event["prev_hash"] = prev_hash
        event["hash"] = event_digest(event)
        prev_hash = event["hash"]
        rebuilt.append(json.dumps(event, sort_keys=True))
    return rebuilt


def _heading(text: str) -> None:
    print(f"\n{text}\n{'-' * len(text)}")


def _var(name: str) -> Path:
    return project_root() / "var" / name


if __name__ == "__main__":
    raise SystemExit(main())
