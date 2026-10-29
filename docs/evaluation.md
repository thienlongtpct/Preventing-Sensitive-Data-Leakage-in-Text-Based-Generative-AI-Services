# Evaluation and regression testing sample

**Contributor:** Pardha Pudi (Group 2)

**Branch:** `pardha-evaluation-and-regression-testing`

**Sample run date:** October 29, 2026

This contribution extends the existing evaluation runner with JSON export,
custom dataset selection, explicit metric population counts, and regression
tests. The gateway, detectors, policies, and synthetic benchmark were already
part of the initial project. This is an initial sample of the evaluation task;
the group still needs to evaluate the final integrated modules.

## Reproduce

Run from the repository root with Python 3.11 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -q
python -m pytest tests/test_evaluation_regression.py -q
python -m privacy_gateway evaluate --output var/evaluation.json
python -m privacy_gateway evaluate --cases data/cases/labeled_cases.jsonl --json
```

`--output` saves the full report as JSON while preserving the readable console
report. `--json` prints JSON instead. `--cases` selects a labeled JSONL file;
omitting it uses the existing benchmark. New output directories are created
automatically. Generated reports include per-case role and service metadata,
decisions, flags, latency, and summaries. They exclude request text, response
text, and labeled leak strings. They retain case IDs and metadata, so use
synthetic identifiers when preparing a dataset for sharing.

Each JSONL record follows the existing case schema: `id`, `text`, `role`,
`service`, `expect_sensitive`, optional `leakage_type`, and optional
`leak_strings`. Use real JSON booleans. A sensitive case without leak strings
contributes to detection metrics but is excluded from attack-success metrics.

## Evaluation method

The same 12 labeled requests run through the same gateway in protected and
unprotected modes: 9 sensitive attack cases and 3 benign cases, for 24 total
requests. Cases cover chat, RAG, and agent services. Covered leakage types are
prompt disclosure, system prompt extraction, training canary extraction,
membership probes, and restricted retrieval. The benchmark uses guest,
employee, and analyst roles; it does not cover admin behavior.

The unprotected run disables policy transformations while retaining detector
execution, input validation, unknown-role rejection, and detector-failure
handling. Its latency is therefore the prototype's unenforced gateway
baseline, rather than the cost of directly calling a model without a gateway.

| Metric | Definition |
| --- | --- |
| Precision | TP / (TP + FP), on protected runs |
| Recall | TP / (TP + FN), on protected runs |
| F1 | 2 × precision × recall / (precision + recall) |
| False-positive rate | FP / (FP + TN), on protected runs |
| Attack success | Cases returning any labeled leak string / cases with leak strings, per mode |
| Benign utility | Benign cases with nonempty output and an allow/warn action / benign cases, per mode |
| Mean latency | Arithmetic mean of gateway-reported milliseconds over all cases in that mode |

The detector prediction is `Result.sensitive`, which includes findings from
input, context, and output. It is not a measure of input-only entity extraction.
A zero denominator returns `0.0` by the existing metric convention; inspect
`attack_cases`, `benign_cases`, and confusion-matrix counts to distinguish
missing populations from measured failure. Benign utility measures response
availability, not answer correctness or quality.

## Recorded sample results

The committed [JSON report](results/pardha_evaluation_sample.json) records one
local run with Python 3.12.6 on macOS ARM64, the default policy, and no optional
detector or privacy packages. Precision, recall, and F1 were each **1.00**;
false-positive rate was **0.00**. Confusion counts: TP=9, FP=0, TN=3, FN=0.

| Mode | Attack success | Benign utility | Mean latency, rounded (ms) |
| --- | --- | --- | --- |
| Protected | 0 / 9 (0%) | 3 / 3 (100%) | 0.07 |
| Unprotected | 9 / 9 (100%) | 3 / 3 (100%) | 0.06 |

The privacy report includes 24 new audit events. Its reported backends are
`laplace-fallback` and `plaintext-fallback`; the risk sum in this run is a
plaintext fallback, not a demonstrated homomorphic encryption result.
Noisy privacy aggregates and latency vary between runs, so they are not
compared to fixed snapshot values in the tests.

## Regression coverage

The original suite contained 17 passing tests. The expanded suite contains
44 passing tests, including 27 in `tests/test_evaluation_regression.py`:

- Twelve individually named benchmark checks verify sensitive detection,
  protected leak removal, a leaking unprotected baseline, and benign utility.
- Metric checks exercise empty labels, missing classes, missed detections,
  mixed confusion counts, and mismatched label lengths.
- A controlled evaluation deliberately includes a missed attack, a false
  positive, a partially leaked response, and a blocked benign request. It
  verifies rate denominators, mean latency, identical requests between modes,
  and exclusion of raw text from exported rows.
- Empty, benign-only, and attack-only evaluations verify missing-population
  behavior. Audit isolation excludes events from before the current run.
- CLI checks verify default/custom datasets, JSON stdout, saved JSON,
  readable output, and automatic creation of the report directory.

## Limitations and next steps

These results describe a small, synthetic simulator benchmark. They do not
establish real-world accuracy or privacy guarantees. Leakage matching is
case-sensitive exact substring matching; paraphrases, encodings, and partial
secrets can evade this metric. The membership case checks canary disclosure,
not a statistical membership-inference attack. The three benign examples are
too few to estimate a general false-positive rate.

Latency comes from one pass with protected requests first and unprotected
requests second; no warmup, repeated trials, or confidence intervals are used.
The gateway's timing excludes the audit append and aggregate privacy report,
so it does not measure complete command execution time. The sub-millisecond
sample values are simulator timings, not production model timings.

Next steps are to add held-out benign and adversarial cases, admin-role and
obfuscated-leakage coverage, repeat latency measurements, and run these
regressions after the other members' components are integrated. The existing
deterministic leak and utility assertions are benchmark expectations, not
claims about arbitrary custom datasets.
