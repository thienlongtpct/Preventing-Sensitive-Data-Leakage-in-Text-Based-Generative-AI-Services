# Task 6: Advanced Attack Simulation

## Overview

Task 6 extends the project with four controlled privacy attack
simulations.

All data, secrets, documents, records, and tools used by these
experiments are synthetic. The simulations run locally and do not
interact with external systems.

The goal is to compare intentionally vulnerable behavior with a
protected configuration.

## Attack Scenarios

### 1. Canary Leakage

A synthetic canary value is planted in simulated model memory.

The vulnerable configuration reproduces the memorized value when an
extraction-style request is received.

The protected configuration detects the canary in model output and
blocks it before it reaches the user.

### 2. Membership-Style Inference

A synthetic member record and non-member record are queried.

The vulnerable configuration exposes different observable scores,
allowing membership to be inferred.

The protected configuration returns uniform observable scores,
preventing the attacker from distinguishing members from non-members.

### 3. Restricted RAG

The simulated retrieval collection contains public and restricted
documents.

The vulnerable configuration returns a relevant restricted document
without applying an authorization boundary.

The protected configuration identifies the restricted document and
prevents its contents from reaching the final response.

### 4. Restricted Agent

The simulated agent has public and restricted tools.

The vulnerable configuration executes a restricted tool and exposes
its synthetic result.

The protected configuration performs an authorization check before
tool execution and denies the restricted invocation.

## Expected Results

| Scenario | Vulnerable Mode | Protected Mode |
|---|---|---|
| Canary leakage | Leaked | Blocked |
| Membership inference | Inferable | Hidden |
| Restricted RAG | Leaked | Blocked |
| Restricted agent | Executed / leaked | Denied |

## Running the Simulation

From the repository root:

```bash
PYTHONPATH=src python -m privacy_gateway.simulator.advanced
