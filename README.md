# Tether — identity drift detection for autonomous AI agents (prototype)

D3COY 1.0 hackathon prototype (team: Unethically). A stdlib-only Python
simulation of the Tether design: an agent's credentials stay valid while its
behavior drifts — Tether detects the drift on behavior and data flow, fuses
deterministic and learned signals into one explained score, and answers with
a graduated response instead of killing the agent.

**v2** adds the identity layer (signed event envelopes, nonce freshness,
delegation certificates, key→role binding), identity-scoped escalation, attacks
a7–a9, and a measurement pipeline with Wilson confidence intervals, a detector
ablation, a deterministic manifest and machine-checked hypotheses. The
authoritative plan is `PLAN_V2.md`; the frozen metrics are `PREREG.md`.

**Everything here is a simulation.** The agent is scripted; there is no LLM
and no network. Numbers come from `results/` and from your own reruns.

## Architecture

```
            declared role contract (L0, the only trusted anchor)
                              |
                              v
   agent tool call -> [ L1 event gateway ] -> allow / hold / narrow /
                          |                   quarantine / isolate / block
                          |
   +--------+--------+--------+--------+----------+
   |        |        |        |        |          |
   v        v        v        v        v          v
 contract provenance baseline intent  context  delegation   (L2 detectors)
   |        |        |        |        | (drift   v
   +--------+--------+--------+--------+) budget) (L3 change channel)
                          |
                          v
            noisy-OR fusion + impact + floors        (L4)
                          |
                          v
            5-rung graduated response, alert card    (L5)
```

The ledger is an append-only SQLite hash chain (`tether/ledger.py`),
tampering is detected by `verify_chain()`.

## Run it

Python 3.10+, standard library only. From this directory:

```bash
# tests
python -m unittest discover -s tests -t . -v

# full evaluation (benign 900, legit-change 100, attacks 200 each, plus
# leave-one-out ablation) -> writes results/ (~80 s)
python -m tether.evaluate --seed 7 --ablation

# verify determinism + seed-11 replication + H1-H9, then docs drift
python verify.py
python docs_check.py

# demo, one scripted session, colored step-by-step log
python -m tether.demo --scenario a1_pdf_injection --mode tether
python -m tether.demo --scenario a2_tool_poisoning --mode none

# API + dashboard (same stdlib server), then open the URL
python -m tether.api
# endpoints: /scenarios, /run?scenario=..&mode=..&n=.., /results, /stream, /, /health
```

On Windows use `py -3` or `python` per your install; target `python -m …`

## Scenarios

- `benign` — ordinary procurement work (900 sessions in the full run).
- `legit_change` — approved change adds `contract_clause_search` (false-alarm
  control, deliberately **not** an attack id).
- `a1_pdf_injection` — poisoned supplier PDF -> HR read -> off-allowlist POST.
  Wording tiers `plain / mild / mimic` vary only the wording.
- `a2_tool_poisoning` — modified tool description drives the same chain.
- `a3_mimicry` — everything inside tools, classes, egress and ceilings
  (bounded but not detected in Phase 1; the Phase-2 drift budget catches it).
- `a4_low_and_slow` — small drip leaks; Phase-1 miss, Phase-2 drift catch.
- `a5_stolen_token` — captured signed-envelope replay from a foreign host.
- `a6_delegation` — procurement A signs an HR grant its own contract denies.
- `a7_persistent` — returns after containment: retry, low-and-slow, hard return;
  exercises the full five-rung ladder and identity-scoped escalation.
- `a8_composition` — every step contract-legal, illegal only as a sequence;
  caught by provenance, not by a contract clause.
- `a9_impersonation` — valid procurement key claiming `hr_agent` / blueprint
  2.0.0; only the key→role/blueprint binding can see it.

## Measured results (generated)

Every number below is generated from `results/results.json`; `docs_check.py`
fails the build if this block drifts. Full tables and intervals:
`results/RESULTS_TABLE.md`.

```
<!-- BEGIN GENERATED CLAIMS (docs_check.py --fix) -->
seed=7 · n=200 sessions/attack · benign=900 · approved_change=100 · unit=session (rates) / records (leak) / ms (latency)
a1_pdf_injection: detected=100.0% [98.1,100.0] caught=100.0% [98.1,100.0] leak_median=0.0 leak_p90=0.0
a2_tool_poisoning: detected=100.0% [98.1,100.0] caught=100.0% [98.1,100.0] leak_median=0.0 leak_p90=0.0
a3_mimicry: detected=0.0% [0.0,1.9] caught=0.0% [0.0,1.9] leak_median=18.0 leak_p90=24.0
a4_low_and_slow: detected=0.0% [0.0,1.9] caught=0.0% [0.0,1.9] leak_median=2.0 leak_p90=3.0
a5_stolen_token: detected=100.0% [98.1,100.0] caught=100.0% [98.1,100.0] leak_median=0.0 leak_p90=0.0
a6_delegation: detected=100.0% [98.1,100.0] caught=100.0% [98.1,100.0] leak_median=0.0 leak_p90=0.0
a7_persistent: detected=95.0% [91.0,97.3] caught=94.5% [90.4,96.9] leak_median=0.0 leak_p90=0.0
a8_composition: detected=100.0% [98.1,100.0] caught=100.0% [98.1,100.0] leak_median=0.0 leak_p90=0.0
a9_impersonation: detected=100.0% [98.1,100.0] caught=100.0% [98.1,100.0] leak_median=0.0 leak_p90=0.0
clean: false_alerts_per_1000_incl_legit_change=0.0 utility=100.0% attack_session_utility=58.8%
identity_arm: a1_pdf_injection=0.0% a2_tool_poisoning=0.0% a3_mimicry=0.0% a4_low_and_slow=0.0% a5_stolen_token=100.0% a6_delegation=100.0% a7_persistent=0.0% a8_composition=0.0% a9_impersonation=100.0%
ladder_total: allow=2545 hold=577 narrow=4 quarantine=6 isolate=1382 block=3
latency: p50=0.215ms p95=0.873ms p99=1.307ms n=11105
hypotheses: H1=PASS H2=PASS H3=PASS H4=PASS H5=PASS H6=PASS H7=PASS H8=PASS H9=PASS
<!-- END GENERATED CLAIMS -->
```

## What is honest

- The text gate (`tether/textgate.py`) is a TF-IDF cosine stand-in, NOT an
  LLM judge, and never the gate inside Tether mode.
- We wrote both the attacks and the detectors; no production traces; the
  agent is scripted. Every caveat is repeated in `results/results.json`.
- Numbers in `results/` are measured, never tuned to targets; detectors,
  thresholds and attacks are fixed before the run and stays fixed.

## Known limits (also in THREAT_MODEL.md)

- Tether bounds blast radius and detects fast; it does not stop injection.
- Mimicry and low-and-slow drip are **Phase-1 misses**; the Phase-2 drift
  budget catches them at 99.5 % / 92.5 % (seed 7, n=200), with a residual tail.
- Identity integrity is HMAC-SHA256 with a local key registry (a stand-in for
  Ed25519), so a5 models replay, not signing-key compromise.
- Escalation is keyed by role identity: the gateway cannot tell "same victim,
  new injection" from "same attacker returned" (D55).
- Paraphrased sensitive data can slip token matching.
- The contract is human-authored; provenance needs a gateway in the data path.

## Layout

- `tether/` — contract, events, ledger, text gate, detectors, fusion,
  ladder, gateway, alert cards, harness, scenarios, evaluate, demo, api.
- `tests/` — unittest suite (coverage: ledger tamper, A1 blocked-before-bytes,
  tier invariance, legit-change silence, day-one guard, drift, delegation).
- `dashboard.html` — single static dark-theme dashboard, served by the API.
- `results/` — written by the evaluation CLI.
