# HISTORY.md â€” append-only checkpoint log

Time source note: the local shell is broken, so `date` cannot run. Timestamps
are recorded as approximate wall-clock text from the session clock
(2026-10-25). Every entry says what was done, what failed, what was learned.

## 2026-10-25 ~00:00 â€” checkpoint 1 (bootstrap)

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
- Final milestone executed: dashboard fixed (all-6-attack chart with
  phase1/phase2 bars + legend, taint labels and detector reasons shown in
  the replay timeline and live stream, alert card rendered from the /run
  response directly instead of a refetch, skipped-step pill style); API
  /run timeline rebuilt from decision_events (real decisions, labels,
  reasons[:2]) instead of raw planned-step tuples; alert card gained
  baseline_maturity (learned/(learned+10)).
- Found and fixed D31: ledger rows_for_session() dropped every decision
  row (Decision bodies carry only event_id, no session). Decisions are now
  attributed to the session of the event they follow; regression test
  added; sample_session_log.jsonl regenerated with 6 events + 6 decisions.
- Verified live: /health, /run (tether+none, labels/reasons/skipped),
  /results (6 attacks, phase2 blocks), /stream SSE (8 events incl. alert
  card), dashboard served with all new markup; a1 mild run shows NARROW at
  hr_db.query (score 70), BLOCK at http.post, leak 0, utility 4/4.
- Tests: 39/39 OK. Evaluation re-run seed 7: identical detection numbers
  (deterministic); latency p50 0.15 ms / p95 0.79 ms / max ~108 ms warmup.
- HANDOFF.md rewritten as FINAL: results table, misses and why, CLAIMS
  CHECK, exact commands, caveats. TODO.md Final box checked. Tagged final.

## Checkpoint (post-final): TRANSFER.md + API hardening

- Added TRANSFER.md: single self-contained transfer doc for the team and
  future LLM sessions — all HTTP endpoints with live-captured request/
  response payloads (/health /contract /scenarios /run GET+POST /stream SSE
  /results), field glossaries (timeline, alert card, results.json),
  dashboard panel->endpoint->DOM-id map, ground rules, and the
  do-not-"fix" caveat list.
- API hardening (D32): parse_run_params() validates mode in
  (none|textgate|tether) — an unknown mode previously fell into the tether
  branch with gateway=None and crashed with a 500; malformed n/seed now
  return clean 400 JSON instead of an unhandled traceback; /run path match
  tightened to exact /run; POST rejects non-dict bodies. 6 new tests;
  suite now 45/45 OK. Verified live: 400 bad mode, 400 bad n, 404 unknown
  scenario, valid run unchanged (a1 mild: detected, alert score 70).

## Checkpoint (post-final): dashboard UI fixes from team screenshot

- Chart label fix: the attack-name labels under the detection chart
  (#chart-names, div.name) are a SIBLING of .chart, so the old
  .chart .name ... selectors never matched and all six labels collapsed
  into one squashed "a1a2a3a4a5a6" string. Selectors now also target
  .name / .name i with flex-basis 60px (= one bar pair width), so
  labels align under their bar pairs again.
- Timeline session grouping: with sessions n>1 the five sessions' steps
  ran together in one flat list (step numbers restarting, no separator).
  Each session now renders as its own div.session block with a div.shead
  header (tier, session id, alert/clean pill, leak, utility, ok/bad accent
  border); its alert card is appended inside the block instead of piling
  up in a single bottom div (#alert removed). Step rows no longer repeat
  the tier prefix; it moved to the header. Run summary table unchanged.
- TRANSFER.md dashboard section updated to match (and warns future editors
  not to re-scope the label rules under .chart).
- Tests: 45/45 OK (HTML not covered by tests; verified live via served
  / response containing new markup and no leftover els.alert references).
