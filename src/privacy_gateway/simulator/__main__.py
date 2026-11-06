"""Command-line entry point for the Task 5 prompt leakage and injection simulator.

    python -m privacy_gateway.simulator run [--json] [--output PATH] [--probes PATH]
    python -m privacy_gateway.simulator generate [--seed N] [--output PATH]
"""

import argparse
import json
import sys
from pathlib import Path

from privacy_gateway.paths import project_root
from privacy_gateway.simulator.probes import DEFAULT_SEED, generate_probes, load_probes, write_probes
from privacy_gateway.simulator.runner import format_report, run_simulation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m privacy_gateway.simulator")
    subparsers = parser.add_subparsers(dest="command")

    run = subparsers.add_parser("run", help="Run probes protected and unprotected")
    run.add_argument("--probes", type=Path, help="Labeled probe JSONL (default: generate from seed)")
    run.add_argument("--seed", type=int, default=DEFAULT_SEED)
    run.add_argument("--json", action="store_true", help="Print the full report as JSON")
    run.add_argument("--output", type=Path, help="Save the full JSON report to this file")

    generate = subparsers.add_parser("generate", help="Write the labeled probe set")
    generate.add_argument("--seed", type=int, default=DEFAULT_SEED)
    generate.add_argument("--output", type=Path, default=project_root() / "data" / "cases" / "attack_probes.jsonl")

    args = parser.parse_args(argv)
    if args.command == "generate":
        probes = generate_probes(args.seed)
        write_probes(args.output, probes)
        print(f"Wrote {len(probes)} probes to {args.output}")
        return 0

    if args.command is None:
        args = run.parse_args([])
    probes = load_probes(args.probes) if args.probes else generate_probes(args.seed)
    report = run_simulation(probes)
    serialized = json.dumps(report, indent=2, allow_nan=False)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + "\n", encoding="utf-8")
    print(serialized if args.json else format_report(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
