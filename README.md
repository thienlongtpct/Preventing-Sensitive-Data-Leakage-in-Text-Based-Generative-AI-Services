# Preventing Sensitive Data Leakage in Text-Based Generative AI Services

Initial Python project for a privacy gateway in front of a simulated text-generating service. The gateway detects sensitive text, applies a role policy, and records a sanitized audit event. Labeled synthetic cases compare a protected run with the same leaky simulator left unprotected.

The simulator, corpus, and canary are fake. Do not add live secrets or private records.

## Layout

```
config/policy.yaml          role actions and protected markers
data/corpus.json            public and restricted synthetic documents
data/tools.json             synthetic agent tool output
data/cases/labeled_cases.jsonl
src/privacy_gateway/        gateway, detectors, policy, audit, evaluation
docs/threat_model.md
docs/architecture.md
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
