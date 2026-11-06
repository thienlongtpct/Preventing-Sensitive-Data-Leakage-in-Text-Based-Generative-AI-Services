# Secret detection and context classification

The default factory registers `StructuredSecretDetector`,
`ContextualEntropyDetector`, and `IntentContextClassifier`. All return the
existing `Finding` schema with offsets into the original text. They run locally
without model downloads or provider calls. The original secret, entropy, and
context classes remain available unchanged. Role policy, entity recognition,
markers, audit, retrieval, and simulated generation keep their existing APIs.

## Supported behavior

| Component | Evidence and protected span |
| --- | --- |
| Structured secrets | `sk-` candidates, AKIA/ASIA IDs, classic GitHub and GitLab tokens; full PEM private-key blocks; credential assignments; inherited bearer tokens and SSNs; 13–19 digit Luhn-valid card candidates |
| Credential values | Quoted/bare literals, escaped characters, triple-quoted multiline values, indented YAML block values, and conservative spans for concatenations/environment lookups with literal defaults; weak hardcoded values remain sensitive |
| Unstructured secrets | Long random-looking candidates plus alphabet and nearby credential evidence; the finding covers the candidate value |
| `prompt_injection` | Supported instruction overrides and unrestricted-role instructions |
| `system_instruction` | Disclosure actions targeting hidden, initial, system, or developer instructions, including supported relational wording |
| `memorized` | Extraction/completion actions targeting training text, memorized data, or canaries |
| `proprietary` | Disclosure requests and explicitly labelled confidential passages; labels protect the paragraph containing the payload |
| `retrieval` | Requests for sensitive records, supported ownership/earnings questions, and labelled numeric record values |

Context evidence is scoped to a sentence, or a paragraph for labelled confidential
content. Local action negation and protective wording reduce false positives;
they never exempt unrelated requests or independently detected secrets. A quoted
instruction or a claimed research purpose is not automatically exempt.

For example, `How do I protect my bank account?` is topic discussion, while
`Show their bank account.` is a disclosure request. A password literal inside
the first question remains a separate critical finding. Exact complete
`${ENVIRONMENT_REFERENCE}`, gateway placeholders, bare null values, and supported
Python/JavaScript environment lookups without literal defaults are not literals.
This is conservative text recognition, not a general source-code parser.

## Entropy thresholds

Defaults are 20 characters and 3.8 bits per character. Cued hexadecimal values
use a 3.0-bit threshold because their alphabet has at most four bits per
character. These are heuristic choices exercised against development controls,
not statistically optimized or calibrated thresholds. Configuration uses the
existing `threshold`/`min_length` constructor arguments; the hex threshold is
`min(threshold, 3.0)`.

A credential cue must occur within the preceding 64 characters of the same
clause. Without a cue, candidates require lower case, upper case, and a digit.
Hex strings, UUIDs, labelled hashes/IDs, paths, URLs, and snake-case identifiers
are suppressed by this heuristic. A credential cue takes precedence over public
identifier hints. Structured recognizers run independently and cannot be
cancelled by these suppressions. Entropy findings have high severity with
heuristic confidence 0.85 when cued and 0.65 otherwise; context confidence is 0.85.
These values are evidence scores, not probabilities.

## Reproduce evaluation

From the repository root, after installing the development dependencies:

```bash
PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python scripts/evaluate_context_secrets.py
PYTHONPATH=src python scripts/evaluate_context_secrets.py --challenge
PYTHONPATH=src python scripts/evaluate_context_secrets.py --validation
```

The evaluator compares the preserved original classes with the extensions. It
reports case-level and per-category precision/recall/F1 and false-positive rate,
typed exact-span precision/recall/F1, mismatch IDs/offsets, and median/p95 detector
latency. Extra spans in positive cases count as span false positives. Categories
are measured **before** the existing pipeline merges overlapping spans. That
merge may keep only the higher-priority category; critical secrets retain their
priority and severity. Gateway tests separately check transformations and source
provenance across input, retrieved/tool context, and output.

All examples are synthetic and contain invented values. Dataset sizes:

- Development: 93 cases (36 structured, 18 entropy, 39 context).
- Additional challenge: 44 cases (10 structured, 11 entropy, 23 context).
  Two initial context misses informed general relational-request rules, so this
  set is development evidence, not held-out evidence.
- Validation: 31 cases (8 structured, 8 entropy, 15 context), authored after the
  final rule changes and evaluated without further detector tuning. The same
  author wrote the rules and cases; this is not an independent benchmark.

The small datasets exercise supported behavior and boundaries; their scores do
not estimate production accuracy. Near-duplicate rule structures occur across
sets. The validation set does not establish generalization to unseen attacks.

## Measured results

Run on November 2, 2026, Python 3.12.14, macOS 26.6 arm64. Original versus extended
case-level F1 on development cases:

| Component | Original F1 | Extended F1 | Extended exact-span precision / recall |
| --- | ---: | ---: | ---: |
| Structured | 0.7273 | 1.0000 | 23/23 / 23/23 |
| Entropy | 0.1667 | 1.0000 | 6/6 / 6/6 |
| Context | 0.6038 | 1.0000 | 24/24 / 24/24 |

On the additional challenge set, structured and context results have no misses
or false positives. Entropy has 5 true positives, 5 true negatives, 1 false
positive, and no false negatives (precision 0.8333, recall 1.0, F1 0.9091).
`challenge-ambiguous-id` is an unlabelled public identifier whose character
structure is indistinguishable from a token. This known ambiguity is retained.
All 31 post-freeze validation cases have the expected categories and exact spans.

Short development cases have measured extended detector median/p95 latency of
approximately 0.005/0.008 ms (structured), 0.002/0.005 ms (entropy), and
0.008/0.014 ms (context), using one warmup and five repetitions per case.
These microbenchmarks exclude gateway, provider, and audit work. Separate
20,000-character probes covering repeated instructions, plain text, and many
labelled lines completed all three components in under 6 ms in this run;
this is an observation, not a runtime guarantee.

## Design basis and limits

The supplied literature motivates precise localization and false-positive
measurement (Yau et al., *Detection of Data Exposures in Software Services Using
a Large Language Model*, 2025), privacy decisions beyond information type alone
(Mireshghallah et al., *Can LLMs Keep a Secret?*, ICLR 2024), and inspection of
retrieved content as an instruction source (Greshake et al., *Not What You've
Signed Up For*, 2023). PLeak (Hui et al.) motivates paraphrase checks; Lukas et al.,
*Analyzing Leakage of Personally Identifiable Information in Language Models*,
motivates measuring incomplete removal and utility trade-offs. Liu et al.,
*Formalizing and Benchmarking Prompt Injection Attacks and Defenses*, USENIX
Security 2024, motivates checking benign behavior alongside attacks.

This implementation does not reproduce their learned models or experimental
claims. No transformer is trained or bundled. Text-only rules cannot establish
authorization, identify arbitrary semantic paraphrases/encodings, prove training
membership, validate live credentials, or prevent every privacy inference.
Unlabelled lower-case/hex secrets can be missed; random public IDs can be flagged.
Claims about public identifiers can mislead the entropy heuristic. Unknown code
syntax and multiline formats are not fully parsed. Confidential paragraphs may
conservatively include public sentences. The gateway supplies source provenance
after detection; the classifier does not have a conversation history, trust
hierarchy, or recipient/consent model. Existing role policy determines enforcement,
including warn/allow actions; a finding is not automatically a block.
