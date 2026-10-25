# HANDOFF.md — Tether v2 (M10 done)

## Status

v1 complete (`final`). M8 framing done, M9 identity layer done (identity arm:
0 % a1-a4, 100 % a5/a6/a9). **M10 done: ladder + a7/a8.** The 5-rung ladder is
now reachable end to end via identity-scoped escalation (`tether/escalation.py`,
D47) with no threshold moved: severity accrues per identity across sessions,
level 1 turns a repeat narrow into quarantine, level 2 turns it into isolate,
and history decays after 25 clean sessions. New attacks: a7 persistent intruder
(three phases: retry / low-and-slow / hard return, D48) and a8 composition chain
(every step contract-legal, caught by provenance tainted-carry, D49).
`results.json` now carries `ladder_usage` per corpus and total (D50).
76/76 tests green.

Measured sanity (seed 7, reduced corpora: 20/attack — NOT the final table):
a7 rungs = allow 45, hold 8, narrow 1, quarantine 1, isolate 8 (H4 holds at this
n; must be re-confirmed at n=200 in M11). a8 100 % caught, 0 leak, 0 contract
violations. a7 p1 50 % / p2 90 %, median leak 2 records (phase-B drip leaks a
little before the drift latch - reported, not hidden). Benign 0 false alerts,
100 % utility, zero isolations.

## NEXT ACTION

M11: evaluation v2. Create `tether/stats.py`, `tether/ablation.py`, `verify.py`,
`docs_check.py`, and the v2 results schema; then regenerate `results/` ONCE
(D39) and check H1-H9 against PREREG.

1. `tether/stats.py`:
   - `wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]` in
     percent; `median_p90(values)`; `cdf_points(values, n=50)`.
2. `tether/ablation.py`:
   - `run_ablation(contract, sessions, arm="tether_p2")` -> leave-one-out over
     `["contract","provenance","identity","delegation","baseline","context","drift","intent"]`
     by passing an `enabled` set into `Gateway` (add `Gateway.enabled: set[str] | None`
     and skip disabled detectors in `evaluate`; do NOT touch weights).
   - Return per attack: detection delta (pp) and false-alert delta.
3. `tether/evaluate.py`: results schema v2 -
   - `ci` per attack (Wilson on detected and caught),
   - `leak_samples_none` / `leak_samples_tether` (full vectors, not just median),
   - `latency_samples_ms` + p99,
   - `drift_trajectory` (per session: destination, records, cusum, latched),
   - `threshold_sweep` (report detection/FP at band edges 30/60/80/92 +/- offsets;
     this is REPORTED sensitivity, never used to pick a threshold),
   - `ablation`, `identity_arm`, `ladder_usage`, `manifest_hash`.
4. `verify.py` (repo root): one command that re-runs the evaluation in a temp
   dir twice and asserts identical `MANIFEST.json` hash + H1-H9 verdicts,
   exit code 0/1, human-readable table.
5. `docs_check.py`: fails if (a) a number in README/HANDOFF/EXHIBITS/exhibit
   captions does not match results.json, (b) a doc links to a missing file,
   (c) test count stated in docs != actual collected tests, (d) PREREG.md has
   been edited after tag `m8` without a deviation row.
6. `results/MANIFEST.json`: seed, counts, sha256 of results.json, python
   version, git commit, and the H1-H9 verdicts.
7. Regenerate `results/` once, then update HANDOFF's measured table with seed,
   n and unit on every number.

Do not tune anything to improve a verdict. If a hypothesis fails, record NOT
SUPPORTED in HANDOFF/CLAIMS CHECK and keep the result.

## How to run and test

```
cmd /c "python -m unittest discover -s tests -t . 2>&1"; echo "EXIT=$LASTEXITCODE"
python -m tether.evaluate --seed 7
python verify.py
python docs_check.py
python -m tether.demo --scenario a7_persistent --mode tether
python -m tether.api            # http://127.0.0.1:8765/
```

## Last test result

2026-10-25 22:01 — `Ran 76 tests ... OK`, EXIT=0 (65 + 11 escalation/ladder/
composition tests).

## Known bugs / watch items

- attack_session_utility fell from v1's 93.2 % because a repeated attacking
  identity now gets escalated (D47). Report it with that explanation; do not
  suppress the escalation to make the number look better.
- a7 median leak is non-zero (phase-B drip before the drift latch). That is the
  cumulative-detection lag, same class of residual as a3/a4; report it.
- v1 caveats unchanged: a3/a4 Phase-1 misses by design; textgate tier artifact
  measured not tuned; a6 fixed parent/child pair; latency max = warm-up.
- Ladder: `enforcement` (capsule block) is counted separately from the five
  policy rungs; do not fold it into `narrow`.
- HMAC stand-in (D33/D44); a5 models replay, not key compromise (D37/D45).

## File map

- PLAN_V2.md, PREREG.md (FROZEN), THREAT_MODEL.md, PROBLEM_STATEMENT.md,
  EXHIBITS.md (E1-E9), HANDOFF.md, HISTORY.md, DECISIONS.md (D1-D50), TODO.md,
  RESUME_PROMPT.md, TRANSFER.md
- tether/identity.py + contract.sig.json — identity layer (M9)
- tether/escalation.py — NEW (M10): EscalationState, severity/levels/decay
- tether/response.py — bands unchanged; `RUNG_FOR` mapping
- tether/gateway.py — identity authority, arm, escalation wiring, block counting
- tether/harness.py — envelope signing, modes, escalation, plan identity fields
- tether/fusion.py — identity weight, `floors` flag (identity arm only)
- tether/evaluate.py — arms, a5 replay seeding, identity_arm, ladder_usage
- tether/sim/scenarios.py — a1-a9 (a7 3-phase, a8 composition, a9 laundering)
- tether/detectors.py, contract.py, ledger.py, textgate.py, alert.py, api.py,
  demo.py, dashboard.html — v1 core, unchanged except where noted
- tests/ — 76 tests in 4 files (+ test_identity.py, test_escalation.py)
- results/ — still v1 artifacts; regenerated once in M11 (D39)
