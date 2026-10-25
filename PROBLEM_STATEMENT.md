# PROBLEM_STATEMENT.md — refined (v2)

The Round 0 problem statement is one line: *"Identity Drift Detection in
Autonomous AI Agents."* That sentence hides three different problems that need
three different mechanisms, and most submissions solve the easiest one and call
it done. This file is the refinement we are willing to defend.

## 1. The sentence, unpacked

An autonomous agent holds a credential. Every action it takes therefore passes
authentication and, usually, authorization. "Drift" is the gap between **what
the credential permits** and **what the role was hired to do**. Detection cannot
live in the permission check, because the permission check is exactly what the
attacker is exploiting. It has to live in the consequences.

We split drift into three classes. Each has a different anchor and a different
failure mode:

| Class | Question | Anchor | Mechanism | Fails when |
|---|---|---|---|---|
| **Scope drift** | did it touch something the role never touches? | contract clauses | deterministic check | the contract is wrong |
| **Purpose drift** | were the steps individually legal but collectively wrong? | provenance + sequence | taint tracking, composition rules | the sequence is genuinely legitimate |
| **Identity drift** | is this actually the agent that is supposed to be acting? | signatures + binding | nonce freshness, key->role binding, delegation certs | the signing key is stolen |

v1 solved scope drift well and purpose drift partly. It had **no identity
layer** - "stolen token" was caught by host heuristics, which is behaviour
wearing an identity costume. That is the gap v2 closes, and the reason the
`identity` arm exists as a control.

## 2. Why the obvious solutions fail (measured, not asserted)

- **Allowlists of tools/data/destinations** are necessary and insufficient: a3
  uses only allowed tools to an allowed destination and is bounded, not caught.
- **Text classifiers / LLM judges** are not the gate. The stand-in text gate is
  measured in this repo and its failure is a lexical artifact (plain text shares
  the purpose verb, paraphrase does not). The literature result is worse: the
  published defenses were bypassed at >90 %.
- **Per-instance behavioural learning** is blind on day one and can be walked by
  a patient attacker (boiling frog). Our baseline is keyed by (role, blueprint)
  with contract-seeded cold start, and it never learns from alerted sessions.
- **Kill-on-alert** fails the PS's own fifth demand. A system that stops
  procurement every time a supplier PDF looks odd has not secured anything.

## 3. What "solved" means here (falsifiable restatement)

Tether is solved *for this prototype* if, on a frozen corpus:

1. the deterministic chains (a1, a2, a8) are caught before the attacker-benefit
   step executes, with zero false alarms on 1 000 legitimate sessions;
2. identity-only evidence catches replay, cert violation and impersonation while
   catching **none** of the content attacks (proving the layer is orthogonal);
3. every rung of the response ladder is reachable and measured, and isolation
   fires only on repeat offense;
4. the cumulative attacks (a3, a4) are detected by the drift budget with a
   residual miss that is reported, not hidden;
5. every number on a slide is produced by `results/`, with seed, n and unit.

Anything not in that list is not claimed.

## 4. Five PS demands -> mechanism -> evidence

| PS demand | Mechanism | Where it is evidenced |
|---|---|---|
| 1. Learn normal behaviour per role | role-keyed baseline + contract pseudo-counts (cold start) | `tests/`, BENCHMARK.md, cold-start case |
| 2. Compare continuously to declared role | gateway evaluates every event; contract + baseline + drift | `ladder_usage`, latency, `results.json` |
| 3. Detect mismatch while creds stay valid | post-auth behavioural + provenance + identity detectors | detection table per attack, identity arm |
| 4. Explain every alert with a risk score | noisy-OR fusion, canonical floors, fixed-template reasons, evidence pointers | `results/sample_alert.json`, alert card |
| 5. Restrict without disrupting legitimate work | 5-rung ladder, narrowed capability set, quarantine re-queue | `utility_preserved_pct`, `attack_session_utility_pct` |

## 5. The claim we actually make

> **Bounded blast radius. Fast detection. Not prevention.**

An injection that lands is not stopped. It is made *unprofitable*: the harmful
transfer is blocked, the capability set shrinks to the job, the identity is
contained on repeat offense, and the ledger proves what happened. Residual risk
is stated in the results: in-contract mimicry and a low-volume drip remain
bounded but not always detected.

## 6. What changed from v1 (and why it is not cosmetic)

| v1 gap | v2 change | Falsifiable test |
|---|---|---|
| ladder top-heavy; isolate unreachable | identity-scoped escalation; quarantine reachable | H4: all five rungs counted in a7 |
| "identity" was behavioural | signed envelopes, nonce cache, delegation certs, key->role binding | H3: identity arm 0 % on a1-a4, high on a5/a6/a9 |
| point estimates only | Wilson CIs, per-detector ablation, tail samples, threshold sweep reported | M11 results schema v2 |
| six attacks | a7 persistent, a8 composition, a9 impersonation | a8 test asserts zero contract violations |
| no artifact for judges | dashboard exhibits + optional deck, all numbers injected | docs_check + manifest hash |
