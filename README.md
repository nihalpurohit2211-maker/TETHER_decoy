# Tether — identity drift detection for autonomous AI agents (prototype)

D3COY 1.0 hackathon prototype (team: Unethically). A stdlib-only Python
simulation of the Tether design: an agent's credentials stay valid while its
behavior drifts — Tether detects the drift on behavior and data flow, fuses
deterministic and learned signals into one explained score, and answers with
a graduated response instead of killing the agent.

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

# full evaluation (benign 900, legit-change 100, attacks 200 each;
# runs in well under 2 minutes) -> writes results/
python -m tether.evaluate --seed 7

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
- `legit_change` — approved change adds `contract_clause_search` (A7 false-alarm test).
- `a1_pdf_injection` — poisoned supplier PDF -> HR read -> off-allowlist POST.
  Wording tiers `plain / mild / mimic` vary only the wording.
- `a2_tool_poisoning` — modified tool description drives the same chain.
- `a3_mimicry` — everything inside tools, classes, egress and ceilings
  (bounded but not detected; the supplier-portal account is modeled as
  attacker-controlled).
- `a4_low_and_slow` — small drip leaks; expected miss, reported honestly.
- `a5_stolen_token` — replay from a foreign host, bulk reads (Phase 2).
- `a6_delegation` — procurement A pushes an HR task to agent B (Phase 2).

## What is honest

- The text gate (`tether/textgate.py`) is a TF-IDF cosine stand-in, NOT an
  LLM judge, and never the gate inside Tether mode.
- We wrote both the attacks and the detectors; no production traces; the
  agent is scripted. Every caveat is repeated in `results/results.json`.
- Numbers in `results/` are measured, never tuned to targets; detectors,
  thresholds and attacks are fixed before the run and stays fixed.

## Known limits (also in PROJECT_BRIEF section 7)

- Tether bounds blast radius and detects fast; it does not stop injection.
- Mimicry inside allowed tools/egress is bounded, not detected by Phase 1.
- Low-and-slow drip is missed in this build; see caveats in results.
- Paraphrased sensitive data can slip token matching.
- The contract is human-authored; provenance needs a gateway in the data path.

## Layout

- `tether/` — contract, events, ledger, text gate, detectors, fusion,
  ladder, gateway, alert cards, harness, scenarios, evaluate, demo, api.
- `tests/` — unittest suite (coverage: ledger tamper, A1 blocked-before-bytes,
  tier invariance, legit-change silence, day-one guard, drift, delegation).
- `dashboard.html` — single static dark-theme dashboard, served by the API.
- `results/` — written by the evaluation CLI.
