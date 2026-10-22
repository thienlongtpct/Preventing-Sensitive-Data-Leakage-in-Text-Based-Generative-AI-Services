# Architecture

The initial system is a local Python service. A command-line interface stands in for the user interface. `PrivacyGateway.handle` is the boundary a later web API can call.

```
user
  -> CLI
    -> PrivacyGateway
         -> detector pipeline
         -> policy engine
         -> simulated chat, RAG, or agent
         -> output inspection
         -> sanitized audit
              -> differential-privacy counts
              -> homomorphic sum of risk scores
```

## Modules

| Path | Proposal component |
| --- | --- |
| `docs/threat_model.md` | Requirements and threat model |
| `docs/architecture.md`, `config/policy.yaml` | Architecture, roles, fail-closed behavior |
| `data/` | Synthetic corpus, tool output, and labeled cases |
| `src/privacy_gateway/detectors/` | Detection engine |
| `src/privacy_gateway/policy/` | Policy actions |
| `src/privacy_gateway/services/` | Leaky simulated LLM, retriever, and tool |
| `src/privacy_gateway/audit/`, `privacy/` | Sanitized audit, Diffprivlib or Laplace noise, TenSEAL or plaintext sum |
| `src/privacy_gateway/evaluation/` | Repeatable comparison and metrics |
| `tests/` | Unit and evaluation tests |

## Request path

1. Detectors label spans with a category, severity, and confidence.
2. The policy assigns an action from the role and the severity. The request action is the most restrictive one.
3. Block stops the call. Redact and tokenize change the text that the model is allowed to see.
4. RAG and agent context is inspected the same way. A restricted record is dropped when the role would block it.
5. The simulator answers. Detectors run on that answer, and the policy is applied again before the user sees it.
6. The audit event keeps the role, service, action, categories, risk score, and latency.

## Detector pipeline

Implemented now:

- Regular expressions for keys, bearer tokens, card numbers, and SSNs
- Shannon entropy for long mixed tokens
- Email and phone patterns
- A phrase classifier for injection, system-prompt requests, canaries, proprietary text, and restricted lookups
- Exact markers for the simulated system prompt and canary

Optional, and unused unless installed:

- Presidio, inside `EntityDetector`
- spaCy person names, when `PRIVGUARD_SPACY=1` and `en_core_web_sm` is installed
- `TransformerContextClassifier`, which is the plug-in point for a fine-tuned model

Presidio and spaCy failures are skipped or caught. A failure in a required detector blocks the request.

## What is still open

- Tighter spans from a trained classifier. The phrase rules currently cover the whole request.
- A web UI on top of `handle`.
- A composed differential-privacy budget. Each published count currently spends epsilon on its own.
- Semantic utility. The harness treats a non-empty allow or warn answer as useful for benign cases.
