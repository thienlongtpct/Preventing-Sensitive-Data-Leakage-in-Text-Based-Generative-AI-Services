# Privacy-preserving audit and risk aggregation

Task 4. This note covers the audit log, the differentially private risk report, and the encrypted aggregation of risk across gateways. It maps to the proposal component "Policy and privacy controls": store only sanitized audit events, add differential privacy to aggregate reports [ii], and demonstrate homomorphic aggregation of encrypted risk scores with TenSEAL [iii].

Code lives in `src/privacy_gateway/audit/` and `src/privacy_gateway/privacy/`. Nothing outside those folders was changed. The gateway, CLI, and evaluation runner call the same functions as before.

## What changed from the starting code

| Issue in the starting code | Now |
| --- | --- |
| Warning text was copied into the log, so restricted record ids such as `C-9` and `E-1001` were stored | Warnings become fixed codes such as `context_removed` and `warn:pii:medium` |
| Log lines could be edited or deleted without a trace | Each line links to the previous one by SHA-256, or HMAC-SHA256 with a key |
| Key generation, encryption, and decryption ran in one function, so no party was kept from the plaintext | Three parties: gateways encrypt, an aggregator adds with the public key only, the auditor decrypts the total |
| Category counts used sensitivity 1, but one event can add to several categories | Each event keeps at most 3 categories, and the noise uses sensitivity 3 |
| The event count was published exactly | The event count is noised like every other statistic |
| Every statistic spent the full epsilon, and nothing limited repeated reports | Epsilon is split across statistics and charged to a persistent budget ledger |
| With diffprivlib installed, `seed` was ignored and `test_privacy_report_shapes` failed | The seed is passed to diffprivlib |
| Only categories seen in the data were reported, which reveals that a category occurred | Every action, category, role, and service is always reported |

## Parties and what each one learns

| Party | Holds | Learns |
| --- | --- | --- |
| Gateway | Its own sanitized events and the auditor's public key | Its own totals |
| Aggregator | Public key and ciphertexts | Nothing in plaintext. The number of gateways and the ciphertext sizes |
| Auditor | CKKS secret key, budget ledger | The exact total across all gateways, never one gateway's total (with 2 or more gateways) |
| Report reader | Published report | Noisy totals with error bars, within the epsilon budget |

The auditor is trusted to add noise before publishing. A dishonest auditor could publish exact totals. Removing that trust would need threshold decryption or secure multiparty computation, which is out of scope.

## Audit log

`AuditStore.append` writes one JSON line per request, with these fields:

```
id  ts  role  service  action  categories  finding_count  latency_ms  protected  risk_score  warnings  seq  prev_hash  hash
```

- `role`, `service`, `action`, and `categories` must be known values, otherwise they are stored as `invalid` or dropped. Free text from a request cannot reach the log through them.
- `ts` is floored to the minute and `latency_ms` is rounded to 0.1 ms, so a line is harder to match to one person's request.
- `hash` covers every other field, and `prev_hash` is the previous line's hash. The first line links to 64 zeros.
- Set `PRIVGUARD_AUDIT_KEY` to make the link an HMAC. Without a key, someone who can write the file can recompute the whole chain. The demo shows this.
- `verify` catches an edited, deleted, inserted, or reordered line. It cannot see lines cut off the end. To catch that, store `head()` (sequence number and hash) somewhere else and pass it back as an anchor.
- `report` refuses to publish from a log that fails verification.

## Differential privacy

The unit of privacy is one audit event. Two logs are neighbors if one has an extra event. Each event is encoded into a fixed 33-slot vector, and the report releases these statistics:

| Statistic | Slots | L1 sensitivity |
| --- | --- | --- |
| `events` | count | 1 |
| `risk_sum` | sum of risk scores, each in [0, 1] | 1 |
| `high_risk` | events with risk at least 0.75 | 1 |
| `actions` | one slot per action, exactly one is set | 1 |
| `categories` | one slot per category, at most `max_categories` set | 3 |
| `by_role` | event count and risk sum per role, plus `other` | 2 |
| `by_service` | event count and risk sum per service, plus `other` | 2 |

Laplace noise with scale `sensitivity / epsilon_i` makes each statistic `epsilon_i`-DP. The `epsilon_i` add up to the report's epsilon (sequential composition). By default `epsilon_i` is proportional to sensitivity, so every published number has the same noise scale, `11 / epsilon` for the full report. Means and rates are computed from the noisy counts after release, which costs no extra budget.

`PrivacyAccountant` keeps a ledger in `var/privacy_ledger.json`. A report that would go over the total is refused before anything is computed. The stored total wins over `--budget`, so a reader cannot reset the period by asking for more. Use `budget --reset` to start a new period on a new log.

The category cap is a policy choice. On the labeled cases, the real gateway never produced more than 2 categories per event, so a cap of 3 drops nothing there.

## Homomorphic aggregation

CKKS through TenSEAL, with polynomial degree 8192 and coefficient moduli `[60, 40, 40, 60]`. That is a 200-bit modulus, about 128-bit security, with 4096 slots. Each gateway adds up its own event vectors and encrypts one 33-slot ciphertext. The aggregator only adds ciphertexts slot by slot, so it needs no Galois or relinearization keys, and only the public key is shared. Cost depends on the number of gateways, not the number of events.

CKKS is approximate. The measured error was below 2e-8 for 5,000 events. Publishing raw CKKS decryptions can leak information about the secret key (Li and Micciancio, 2021). Here only the auditor sees raw decryptions, and everything published has Laplace noise added first.

Without TenSEAL, a plaintext fallback with the same three classes runs, and reports name it `plaintext-fallback`.

## Commands

```bash
python -m privacy_gateway.privacy demo        # audit, tampering, encryption, DP budget end to end
python -m privacy_gateway.privacy verify      # check var/audit.jsonl, print an anchor
python -m privacy_gateway.privacy report      # DP report from var/audit.jsonl, charges the ledger
python -m privacy_gateway.privacy report --stats events,actions --epsilon 0.5
python -m privacy_gateway.privacy budget      # show the ledger, or --reset --total 3
python -m privacy_gateway.privacy benchmark   # tables and charts in var/privacy_benchmark/
```

The team commands `evaluate` and `report` still work and now use the new pipeline.

Setup: `pip install -e ".[dev,privacy]" matplotlib`. diffprivlib 0.6.6 fails to import with scikit-learn 1.8 or later, so also run `pip install "scikit-learn<1.8"`. Without diffprivlib the code quietly uses its own Laplace sampler.

## Results

From `python -m privacy_gateway.privacy benchmark`, with 200 trials per point, synthetic events whose actions follow `config/policy.yaml`, and the full 7-statistic report.

Mean absolute error of the published block rate, in percentage points:

| events | epsilon 0.1 | 0.5 | 1 | 5 |
| ---: | ---: | ---: | ---: | ---: |
| 500 | 19.0 | 4.3 | 2.2 | 0.43 |
| 5,000 | 2.2 | 0.43 | 0.21 | 0.04 |
| 50,000 | 0.21 | 0.04 | 0.02 | < 0.01 |

Error falls as 1 / (epsilon × events). At epsilon 1, a report over 5,000 events or more is accurate to about a fifth of a point. A log of a few hundred events is mostly noise; at 500 events and epsilon 0.1 the error is held near 19 points only because rates are clipped to [0, 1]. `report` prints a warning when noise is that large.

Category cap at epsilon 1 and 50,000 events: a cap of 1 gives 38.5% relative error from dropped categories, a cap of 3 gives 3.8%, and caps of 4 and above give 0.2 to 0.3%. With 5,000 events, caps above 4 get slightly worse because the extra sensitivity only adds noise.

Encrypted aggregation, 5,000 events:

| gateways | encrypt, all gateways | aggregate | decrypt | sent to aggregator |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 7 ms | 6 ms | 0.8 ms | 323 KB |
| 8 | 53 ms | 7 ms | 0.8 ms | 2.5 MB |
| 32 | 211 ms | 14 ms | 0.8 ms | 10.1 MB |

Each gateway pays about 7 ms and sends one 323 KB ciphertext, whatever its event count. The public key is 454 KB.

Charts: `dp_error_vs_epsilon.png`, `category_cap_tradeoff.png`, `he_time_vs_gateways.png` in `var/privacy_benchmark/`.

## Limitations

- DP protects one event, not one user. A user who sends many requests is protected less. User-level DP would need user ids in the log and a cap on events per user.
- Composition is basic sequential. Rényi or advanced composition would allow more reports for the same guarantee.
- The hash chain assumes one writer. Concurrent processes appending to the same file can fork the chain.
- The fallback Laplace sampler is a plain inverse-CDF sampler. It is not hardened against floating-point attacks on Laplace noise, so treat it as a demo.
- All parties run in one process. The serialized contexts and ciphertexts are what would cross the network.
- Benchmark events are synthetic. The demo uses the real gateway on the labeled cases with sampled roles.
