# PROBLEM_STATEMENT.md (v2)

The Round 0 problem statement is one line: *"Identity Drift Detection in
Autonomous AI Agents."* That sentence hides three different problems that need
three different mechanisms. This file is our refinement.

## 1. Unpacking the sentence

An autonomous agent holds a credential. Every action it takes therefore passes
authentication and, usually, authorization. "Drift" is the gap between what the
credential permits and what the role was hired to do. Detection cannot live in
the permission check, because the permission check is exactly what the attacker
is exploiting. It has to live in the consequences.

We split drift into three classes. Each has a different anchor and a different
failure mode:

| Class | Question | Anchor | Mechanism | Fails when |
|---|---|---|---|---|
| Scope drift | did it touch something the role never touches? | contract clauses | deterministic check | the contract is wrong |
| Purpose drift | were the steps individually legal but collectively wrong? | provenance and sequence | taint tracking, composition rules | the sequence is genuinely legitimate |
| Identity drift | is this actually the agent that is supposed to be acting? | signatures and binding | nonce freshness, key-to-role binding, delegation certs | the signing key is stolen |

v1 solved scope drift well and purpose drift partly. It had no identity layer.
"Stolen token" was caught by host heuristics, which is behavior wearing an
identity costume. v2 closes that gap, and that is why the `identity` arm exists
as a control.

## 2. Why the obvious approaches fail (measured, not asserted)

- Allowlists of tools, data and destinations are necessary and insufficient. a3
  uses only allowed tools and an allowed destination. It is bounded, not caught.
- Text classifiers and LLM judges are not the gate. The stand-in text gate is
  measured in this repo; its failure is a lexical artifact (plain text shares
  the purpose verb, paraphrase does not). The literature result is worse: the
  published defenses were bypassed at over 90 %.
- Per-instance behavioral learning is blind on day one and can be walked by a
  patient attacker (boiling frog). Our baseline is keyed by (role, blueprint)
  with contract-seeded cold start, and it never learns from alerted sessions.
- Kill-on-alert fails the problem statement's own fifth demand. A system that
  stops procurement every time a supplier PDF looks odd has not secured
  anything.

## 3. What "solved" means here

Tether is solved for this prototype if, on a frozen corpus:

1. the deterministic chains (a1, a2, a8) are caught before the attacker-benefit
   step executes, with zero false alarms on 1,000 legitimate sessions;
2. identity-only evidence catches replay, cert violation and impersonation while
   catching none of the content attacks, which shows the layer is orthogonal;
3. every rung of the response ladder is reachable and measured, and isolation
   fires only on repeat offense;
4. the cumulative attacks (a3, a4) are detected by the drift budget, with a
   residual miss that is reported rather than hidden;
5. every number on a slide comes from `results/`, with seed, n and unit.

We do not claim anything outside that list.

## 4. Five PS demands, mechanisms and evidence

| PS demand | Mechanism | Where it is evidenced |
|---|---|---|
| 1. Learn normal behavior per role | role-keyed baseline plus contract pseudo-counts (cold start) | `tests/`, `BENCHMARK.md`, cold-start case |
| 2. Compare continuously to declared role | gateway evaluates every event; contract, baseline and drift | `ladder_usage`, latency, `results.json` |
| 3. Detect mismatch while creds stay valid | post-auth behavioral, provenance and identity detectors | detection table per attack, identity arm |
| 4. Explain every alert with a risk score | noisy-OR fusion, canonical floors, fixed-template reasons, evidence pointers | `results/sample_alert.json`, alert card |
| 5. Restrict without disrupting legitimate work | five-rung ladder, narrowed capability set, quarantine re-queue | `utility_preserved_pct`, `attack_session_utility_pct` |

## 5. The claim we make

> Bounded blast radius. Fast detection. Not prevention.

An injection that lands is not stopped. It is made unprofitable: the harmful
transfer is blocked, the capability set shrinks to the job, the identity is
contained on repeat offense, and the ledger proves what happened. Residual risk
is stated in the results. In-contract mimicry and a low-volume drip stay bounded
but are not always detected.

## 6. What changed from v1

| v1 gap | v2 change | Test |
|---|---|---|
| ladder top-heavy; isolate unreachable | identity-scoped escalation; quarantine reachable | H4: all five rungs counted in a7 |
| "identity" was behavioral | signed envelopes, nonce cache, delegation certs, key-to-role binding | H3: identity arm 0 % on a1-a4, high on a5/a6/a9 |
| point estimates only | Wilson CIs, per-detector ablation, tail samples, threshold sweep | M11 results schema v2 |
| six attacks | a7 persistent, a8 composition, a9 impersonation | a8 test asserts zero contract violations |
| no artifact for judges | dashboard exhibits, all numbers injected | docs_check plus manifest hash |
