# Threat model

This note is the initial requirements and threat model for the privacy gateway. It covers the simulated service only. Test data is synthetic. Do not put live secrets, customer records, or production prompts in the corpus.

## Assets

- User prompts and uploaded text
- Model outputs
- Retrieved records and tool results
- A simulated memorized canary standing in for training data
- Credentials, card numbers, and national identifiers
- The simulated system prompt

## Roles

| Role | Trust | Critical secrets | High-risk requests |
| --- | --- | --- | --- |
| guest | Lowest | Block | Block |
| employee | Internal user | Block | Redact |
| analyst | Can see a stable token | Tokenize | Warn |
| admin | Operator | Redact | Allow |

Admin is not a bypass. Critical values are still removed from the text that is returned.

## Trust boundaries

The gateway is the enforcement point. The simulated model is treated as leaky on purpose, so the same model can be run with protection off. Retrieved documents and tool outputs are untrusted content and are inspected before they are given to the model. The audit log stores categories, actions, and risk scores. It does not store raw prompts or secret values. If a required detector fails, the gateway blocks the request.

## Leakage paths in scope

- Prompt and file disclosure: sensitive values in the user text come back in the answer
- Training-data extraction: the simulator returns a planted canary when asked
- Membership-style probe: a labeled question about that canary, checked only against this simulator
- RAG extraction: a restricted synthetic record is copied into the answer
- Indirect prompt injection: untrusted text tells the model to ignore instructions
- System-prompt leakage: the answer contains the simulated system prompt or its escalation code

Image generation, audio, federated learning, and explainable-AI interfaces are out of scope.

## Policy actions

Allow, warn, redact, tokenize, and block. Redact replaces a span with a category label. Tokenize replaces it with an HMAC prefix so the raw value is not shown. Block returns no model output.

## Ethical limits

Use synthetic or public data. The labeled probes run against this local simulator so the group can compare protected and unprotected configurations. They are not a client for attacking a deployed model, a real retrieval database, or another organization's prompts.
