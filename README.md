# Tether

Identity drift detection for autonomous AI agents. D3COY 1.0 Round 0, team
Unethically.

Tether watches what an agent does after it authenticates. The credentials stay
valid while the behavior drifts, so permission checks keep passing. Tether scores
the drift from behavior and data flow, fuses deterministic and learned signals
into one explained score, and responds in steps instead of killing the agent.

This is the v2 prototype. v2 adds the identity layer (signed event envelopes,
nonce freshness, delegation certificates, key-to-role binding), identity-scoped
escalation, attacks a7-a9, and the measurement pipeline: Wilson intervals,
detector ablation, a deterministic manifest and checked hypotheses. `PLAN_V2.md`
has the plan. `PREREG.md` has the frozen metrics.

The judge material is generated, not hand-drawn. `tether/exhibits.py` renders
nine SVGs and `results/exhibits/INDEX.json` from `results/`, and the dashboard
serves them. `python -m tether.exhibits --check` (also run by `docs_check.py`)
fails if a figure or caption is stale or edited.

Everything here is a simulation. The agent is scripted, there is no LLM in the
core, and nothing touches the network. Numbers come from `results/` or from your
own rerun.

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

The ledger is an append-only SQLite hash chain (`tether/ledger.py`).
`verify_chain()` detects tampering.

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

# dashboard exhibits (deterministic SVG + captions)
python -m tether.exhibits --write
python -m tether.exhibits --check

# demo, one scripted session, colored step-by-step log
python -m tether.demo --scenario a1_pdf_injection --mode tether
python -m tether.demo --scenario a2_tool_poisoning --mode none

# API + dashboard (same stdlib server), then open the URL
python -m tether.api
# endpoints: /, /health, /contract, /scenarios, /run, /stream, /results,
#            /exhibits, /exhibits/<name>.svg  (see openapi.json)
```

On Windows use `py -3` or `python` per your install.

## Dashboard and exhibits

`python -m tether.api` serves the single-file D3COY dashboard at
`http://127.0.0.1:8765/`. There are two separate surfaces:

- **E1-E9 measured exhibits**: generated SVGs loaded from `/exhibits`. The
  caption, source path, unit and n under each figure come from
  `results/exhibits/INDEX.json`; the page computes no aggregate. Deep link:
  `/?exhibit=latency` (also `detection`, `leak`, `cusum`, `ablation`, `ladder`,
  `latency`, `identity`, `attackmap`, `utility`).
- **Live replay**: one simulated session, stepped with prev/next/play. It is
  labelled as live output, not as the seed-7 benchmark.

If `results/` or `results/exhibits/` is missing, the page shows an explicit
`NO MEASURED RESULTS` state with the regeneration commands. It does not
substitute zeros or placeholder charts. The API contract is `openapi.json`:
ten routes, and the exhibit route accepts only the nine declared basenames.

`vercel.json` serves the dashboard and measured results as static files. The
exhibits and charts work there. Live replay still needs the Python API, so the
static deployment shows a message pointing at `python -m tether.api`.

## Scenarios

- `benign`: ordinary procurement work (900 sessions in the full run).
- `legit_change`: approved change adds `contract_clause_search`. This is the
  false-alarm control, not an attack id.
- `a1_pdf_injection`: poisoned supplier PDF -> HR read -> off-allowlist POST.
  Wording tiers `plain / mild / mimic` vary only the wording.
- `a2_tool_poisoning`: a modified tool description drives the same chain.
- `a3_mimicry`: everything inside tools, classes, egress and ceilings. Bounded
  but not detected in Phase 1; the Phase-2 drift budget catches it.
- `a4_low_and_slow`: small drip leaks. Phase-1 miss, Phase-2 drift catch.
- `a5_stolen_token`: captured signed-envelope replay from a foreign host.
- `a6_delegation`: procurement A signs an HR grant its own contract denies.
- `a7_persistent`: returns after containment (retry, low-and-slow, hard
  return). Exercises the full five-rung ladder and identity-scoped escalation.
- `a8_composition`: every step is contract-legal, illegal only as a sequence.
  Caught by provenance, not by a contract clause.
- `a9_impersonation`: valid procurement key claiming `hr_agent` / blueprint
  2.0.0. Only the key-to-role and blueprint binding can see it.

## Measured results (generated)

Every number below is generated from `results/results.json`. `docs_check.py`
fails the build if this block drifts. Full tables and intervals live in
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
latency: p50=0.215ms p95=0.873ms p99=1.307ms max=130.682ms n=11105
ablation: largest_caught_loss=99.5pp removed=drift attack=a3_mimicry (0 = no measured loss on that corpus)
hypotheses: H1=PASS H2=PASS H3=PASS H4=PASS H5=PASS H6=PASS H7=PASS H8=PASS H9=PASS
<!-- END GENERATED CLAIMS -->
```

## Benchmark

`BENCHMARK.md` is the benchmark card for judges: what was measured, how to read
it, threats to validity, and the reproduce commands. Its numbers are generated
from `results/results.json` and enforced by `docs_check.py`. Full tables with
intervals are in `results/RESULTS_TABLE.md`; the figures are in
`results/exhibits/`.

## Claims check v2

Every number here appears in the generated block above or in
`results/results.json`. "Supported" means supported on this simulated corpus at
seed 7, not in production.

| Claim | Evidence | Status |
|---|---|---|
| Gate latency under 5 ms | p95 0.873 ms, p99 1.307 ms, n=11,105 | **PARTIAL**: true at p95/p99; the 130.682 ms max is first-decision warm-up and is disclosed |
| Zero bytes leaked on a1 and a2 | tether arm: leak median 0.0, p90 0.0 records/session (no-defense median 148 / 131) | **SUPPORTED for records**: leak is measured in records, not bytes |
| Zero false alerts on approved change | 0.0 per 1,000 including approved change; 0 benign isolations | **SUPPORTED** |
| Core work continues under containment | benign/approved-change utility 100.0 % [99.94, 100.00] | **SUPPORTED** for legitimate work. Attack-session utility 58.8 % is the containment cost (D55), not a false alert |
| Mimicry is bounded, not detected | a3 Phase 1 0.0 % (leak unchanged); Phase 2 99.5 % | **SUPPORTED** as stated; Phase 2 detects it |
| Low-and-slow is caught | a4 Phase 1 0.0 %; Phase 2 92.5 % | **PARTIAL**: caught only with the drift budget, and 7.5 % of sessions still miss |
| Every response rung is reachable | allow/hold/narrow/quarantine/isolate/block all non-zero | **SUPPORTED** (counts, not rates) |
| Identity layer handles replay, bad delegation, impersonation | identity arm 100 % on a5/a6/a9; 0 % on a1-a4 by design | **SUPPORTED** on this corpus. It does not detect signing-key compromise |
| The run is deterministic | H6 PASS: two runs produce the same digest and manifest hash | **SUPPORTED** (`results/VERIFY.json`) |
| Attack-session utility is 58.8 % | escalation across separately evaluated corpora | **DISCLOSED LIMITATION** (D55), not a defect to hide or tune |

## What the data does not show

- The text gate (`tether/textgate.py`) is a TF-IDF cosine stand-in, not an LLM
  judge, and never the gate inside Tether mode.
- We wrote both the attacks and the detectors. There are no production traces,
  and the agent is scripted. The same caveats are repeated in
  `results/results.json`.
- Numbers in `results/` are measured, not tuned to targets. Detectors,
  thresholds and attacks were fixed before the run and stay fixed.

## Known limits (also in THREAT_MODEL.md)

- Tether bounds blast radius and detects fast. It does not stop injection.
- Mimicry and the low-and-slow drip are Phase-1 misses. The Phase-2 drift
  budget catches them at 99.5 % / 92.5 % (seed 7, n=200), with a residual tail.
- Identity integrity uses HMAC-SHA256 with a local key registry (a stand-in for
  Ed25519), so a5 models replay, not signing-key compromise.
- Escalation is keyed by role identity. The gateway cannot tell "same victim,
  new injection" from "same attacker returned" (D55).
- Paraphrased sensitive data can slip token matching.
- The contract is human-authored. Provenance needs a gateway in the data path.
- The latency maximum (130.682 ms) is first-decision warm-up. Quote p95/p99.
  Do not present the maximum as steady-state overhead.

## Layout

- `tether/`: contract, events, ledger, text gate, detectors, fusion, ladder,
  gateway, alert cards, harness, scenarios, evaluate, demo, api.
- `tether/exhibits.py`: nine SVG renderers, captions, `--write`/`--check`.
- `tests/`: unittest suite (ledger tamper, A1 blocked-before-bytes, tier
  invariance, legit-change silence, day-one guard, drift, delegation,
  exhibits/API/OpenAPI contract).
- `dashboard.html`: single-file D3COY dashboard, served by the API.
- `BENCHMARK.md`, `openapi.json`, `EXHIBITS.md`: judge package.
- `results/`: measured artifacts, MANIFEST, VERIFY, RESULTS_TABLE, exhibits/.
- `PREREG.md`, `THREAT_MODEL.md`, `PLAN_V2.md`, `DECISIONS.md`: frozen metrics,
  adversary model, plan, decision log.
