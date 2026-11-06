# Preventing Sensitive Data Leakage in Text-Based Generative AI Services

Initial Python project for a privacy gateway in front of a simulated text-generating service. The gateway detects sensitive text, applies a role policy, and records a sanitized audit event. Labeled synthetic cases compare a protected run with the same leaky simulator left unprotected.

The simulator, corpus, and canary are fake. Do not add live secrets or private records.

## Layout

```
config/policy.yaml          role actions and protected markers
data/corpus.json            public and restricted synthetic documents
data/tools.json             synthetic agent tool output
data/cases/labeled_cases.jsonl
data/cases/attack_probes.jsonl              generated prompt leakage and injection probes
src/privacy_gateway/        gateway, detectors, policy, audit, evaluation
src/privacy_gateway/simulator/              attack simulators (Tasks 5 and 6)
docs/threat_model.md
docs/architecture.md
docs/detection.md                           secret detection and context classification
docs/privacy_audit.md                       privacy-preserving audit and risk aggregation
docs/prompt_leakage_injection_simulator.md  Task 5 design and results
docs/advanced_attack_simulation.md          Task 6 canary, membership, RAG and agent attacks
docs/evaluation.md                          evaluation and regression testing
tests/
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

`make test` also works with `PYTHONPATH=src` after `pip install -r requirements.txt`.

With [uv](https://docs.astral.sh/uv/), `uv sync --extra dev` installs from `uv.lock` and `uv run pytest` runs the tests.

Optional packages, not required to run:

```bash
pip install -e ".[detectors,privacy]"
```

`detectors` adds Presidio and spaCy. `privacy` adds Diffprivlib and TenSEAL. Without them, entity rules, Laplace noise, and a plaintext risk sum are used. The report names which backend ran.

## Commands

```bash
python -m privacy_gateway demo
python -m privacy_gateway check --role guest --service chat --text "My SSN is 123-45-6789"
python -m privacy_gateway evaluate
python -m privacy_gateway report
```

`evaluate` prints precision, recall, F1, false-positive rate, attack success, benign utility, and latency for the protected and unprotected configurations. Attack success means a labeled secret string was still present in the text returned to the user.

Pardha Pudi's [evaluation and regression testing sample](docs/evaluation.md) documents
the metric definitions, per-case checks, measured results, and limitations. Save a
report or evaluate another labeled dataset with:

```bash
python -m privacy_gateway evaluate --output var/evaluation.json
python -m privacy_gateway evaluate --cases data/cases/labeled_cases.jsonl --json
python -m pytest tests/test_evaluation_regression.py -q
```

## Attack simulators

```bash
python -m privacy_gateway.simulator run                # Task 5: prompt leakage and injection
python -m privacy_gateway.simulator run --json --output var/attack_report.json
python -m privacy_gateway.simulator generate           # rewrite data/cases/attack_probes.jsonl
python -m privacy_gateway.simulator.advanced           # Task 6: advanced privacy attacks
```

Task 5 sends 192 seeded probes (5 strategies, direct/RAG/tool channels, 4 roles, reworded requests, benign controls) through the gateway with protection on and off. It reports attack success, detection, bypasses, and benign utility by strategy, channel, role, and task. See [docs/prompt_leakage_injection_simulator.md](docs/prompt_leakage_injection_simulator.md).

## Roles

| Role | Critical | High | Medium | Low |
| --- | --- | --- | --- | --- |
| guest | block | block | redact | warn |
| employee | block | redact | redact | allow |
| analyst | tokenize | warn | warn | allow |
| admin | redact | allow | allow | allow |

Unknown roles and required detector failures block the request.

## Services

- `chat` answers from the simulated model
- `rag` retrieves `data/corpus.json`, then answers
- `agent` returns a synthetic tool record when the request names its id, then answers

The model is intentionally leaky. Protection is the gateway in front of it.
