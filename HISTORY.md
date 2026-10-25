# HISTORY.md — append-only checkpoint log

Time source note: the local shell is broken, so `date` cannot run. Timestamps
are recorded as approximate wall-clock text from the session clock
(2026-10-25). Every entry says what was done, what failed, what was learned.

## 2026-10-25 ~00:00 — checkpoint 1 (bootstrap)

- Read tether_build_prompt.md fully, then PROJECT_BRIEF.md fully.
- Created the five handoff files (this protocol) in the project root.
- BLOCKED, IMPORTANT: the local shell is broken. Every terminal command
  (including `echo hello`) exits with code 53 and produces no output. Git
  init/commit/tag cannot run yet; tests cannot run yet. tool `move_to_cloud`
  was attempted to continue in a VM; it was refused by the runtime with
  "Windows command owner is missing. Run bun scripts/build-windows-command.ts
  in freebuff-desktop." That is an app-level repair outside this workspace.
- Learned: when the shell becomes available, first actions are:
  1. run the test suite, 2. repair anything it exposes, 3. `git init` and
  commit the bootstrap per checkpoint rules, 4. tag milestones as they land.
- Decision of record: continue building the standard-library simulation by
  writing source and tests with the file tools so that the moment the shell
  works, `python -m unittest discover -s tests -t .` and the evaluation end
  points can run immediately. Nothing has been executed yet; every result in
  HANDOFF.md is therefore UNMEASURED until the suite runs.

## 2026-10-25 ~01:10 - checkpoint 2 (first execution, measurement bugs fixed)

- Shell works in this session (prior session's exit-53 blocker gone). Ran the
  suite: 17/37 passed initially. Fixed: missing tests/__init__.py, missing
  dataclasses import in tether/ledger.py, missing stopword filter in
  tether/textgate.py (function words dominated the tiny idf corpus), and a
  test calling self._run_a1 as a module function. 37/37 then 38/38 green.
- First real evaluation run (seed 7, 11 s). Read the numbers and found four
  measurement bugs (fixed, never number-tuned):
  1. textgate mode gated every step's statement, making the tier metric
     degenerate (100/100/100). Now screens document CONTENT at the ingestion
     step only; poisoned steps run only if the injection vector executed.
     Measured tiers now: plain 0%, mild 100%, mimic 0% - a genuine lexical
     artifact (plain text contains the purpose verb 'send'), kept and
     reported, not retuned.
  2. Drift budget watched raw bytes only; A4's drip (250-500 B) is below the
     benign anchor so it could never trip. Rebuilt: per-session standardized
     CUSUM on outbound RECORD volume, h calibrated on null traffic
     (calibrate_drift.py: h=8 gives 0.13 trips/1000 sessions), alarm latches
     and resets only via modeled sponsor review (R=10 sessions) unless
     attempted volume stays above anchor (attackers keep pushing; ordinary
     senders do not).
  3. A6's delegation envelope (150 HR records to the child agent) was not
     marked leak=True, so the attack did nothing in none mode.
  4. Intermediate states measured along the way: per-event CUSUM was a
     driftless walk (A4 43.5%); unlatched self-clearing CUSUM cycled (A4
     51%); pure latch flagged 326/1000 benign sessions after one fluke trip.
     Final design: 0/1000 benign false alerts, A4 92.5% contained.
- Measured results (seed 7): A1/A2/A5/A6 100% detected, 0 leak; A3 0% p1
  (by design) / 99.5% p2; A4 0% p1 (expected) / 92.5% p2; benign utility
  100% both phases; attack utility 93.2% (routine emails held while a
  destination is under drift containment - honest cost, reported).
- Learned: latch-without-review converts one statistical fluke into hundreds
  of false alerts; review-with-evidence keeps attack containment near 100%
  while bounding benign damage to R sessions per fluke.
