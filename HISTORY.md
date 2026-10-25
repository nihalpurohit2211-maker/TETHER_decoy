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
  future LLM sessions � all HTTP endpoints with live-captured request/
  response payloads (/health /contract /scenarios /run GET+POST /stream SSE
  /results), field glossaries (timeline, alert card, results.json),
  dashboard panel->endpoint->DOM-id map, ground rules, and the
  do-not-"fix" caveat list.
- API hardening (D32): parse_run_params() validates mode in
  (none|textgate|tether) � an unknown mode previously fell into the tether
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

## 2026-10-25 21:43 � v2 M8: framing (PREREG, THREAT_MODEL, problem statement, exhibits)

- Added PLAN_V2.md (copy of the authoritative v2 plan; commit b0a692a) so the
  handoff is self-contained.
- Baseline verified before any v2 work: `python -m unittest discover` -> 45/45 OK.
- M8 docs written, no code touched:
  - PREREG.md � FROZEN at tag m8, before any v2 detector/attack/ladder change.
    Corpus (900 benign, 100 legit_change, 200/attack, seed 7 primary; 11/23
    replication), five arms (none/textgate/tether_p1/tether_p2/identity),
    twelve metric definitions, H1-H9 with explicit support thresholds, honest
    pre-registered attack expectations, and a "what we will not do after seeing
    results" list. Wilson 95% CIs mandated; no n=1 anecdotes, no pooled seeds.
  - THREAT_MODEL.md � assets, trust boundaries, adversary profiles P1-P9,
    frozen a1-a9 catalogue with expected catcher and rung, three worked
    distinctions (a5 replay vs a9 impersonation; a7 needs history not a bigger
    floor; a8 is sequence-illegal while every clause is legal), explicit
    out-of-scope list incl. key compromise and injection prevention, and an
    assumption->failure-mode table.
  - PROBLEM_STATEMENT.md � splits "identity drift" into scope / purpose /
    identity drift with one anchor and one failure mode each; maps the PS's five
    demands to mechanism and evidence; states the claim as bounded blast radius
    + fast detection, NOT prevention; tables the v1 gaps vs falsifiable tests.
  - EXHIBITS.md � E1-E9 judge exhibits, each with its exact results/ path, unit
    and n, caption rules (misses captioned as misses; identity caption must
    carry the key-compromise limitation).
- Two stale drifts recorded and cleaned (D40): TODO.md still claimed a broken
  shell / "nothing left to write" while git had 8 commits; HANDOFF.md file map
  said 39 tests vs 45. TODO.md replaced with the M8-M14 checklist, HANDOFF.md
  rewritten for v2 with a precise NEXT ACTION (tether/identity.py + exact API).
- DECISIONS added: D33 HMAC-SHA256 stand-in (no public-key verify, no
  non-repudiation), D34 pre-registration freeze, D35 primary/secondary detection
  metric, D36 identity arm = detector-only control, D37 a5 = replay not key
  compromise, D38 attack id map (a7/a8/a9; legit_change is not an a-id),
  D39 one-time v2 results reset (v1 recoverable from tag `final`), D40 doc drift.
- Tests: 45/45 OK. No behavior changed, so no results regeneration.

## 2026-10-25 21:56 � v2 M9: identity layer (signed envelopes, nonce, certs, binding)

- New tether/identity.py (stdlib only, deterministic): HMAC-SHA256 canonical-JSON
  envelopes with key->role/blueprint binding; NonceCache (capacity 20k, logical
  tick, no wall clock); DelegationCert signed by the parent; IdentityAuthority
  bundling registry + freshness + certs + contract; identity_check() returning
  DetectorResult; signed-contract verification (contract.sig.json, tamper-
  evident only, D44).
- Wired: Event gains `envelope` (additive, D46); harness signs every step for
  tether/identity modes and grows plan fields (identity, declared_role,
  declared_blueprint, nonces, delegation); gateway gains identity authority +
  arm; fusion gains identity weight 0.95 and a `floors` flag.
- New `identity` control arm in evaluate (D41: canonical floors OFF, because
  the restricted-class floor is contract policy and would fake identity
  detection on a1-a4). a5 nonces pre-seeded as a captured batch (D45); a9
  (identity laundering) added in M9 because it is the layer's acceptance test
  (D42), a7/a8 stay M10.
- First measurement of H3 (reduced corpus 40/attack, seed 7): identity arm
  a1 0 %, a2 0 %, a3 0 %, a4 0 %; a5 100 %, a6 100 %, a9 100 %; false alerts
  0/1000 ordinary and 0/1000 incl. legit change. Full tether arm unchanged on
  a1-a4 (a1 100/0 leak, a2 100/0, a3 p1 0 -> p2 97.5, a4 p1 0 -> p2 90).
  These are sanity numbers, not the final table (regenerated once at M11).
- Tests: 45 -> 65, all green. New tests: tampered payload, unknown key, key
  substitution, role/blueprint mismatch, replay (incl. seeded captured batch),
  bounded nonce cache, legit delegation no-FP, forged grant, expired cert,
  missing cert, child mismatch, contract signature (good/tampered/wrong sig),
  end-to-end identity-arm matrix.
- Watch: a5 now isolates on first event (identity replay + context
  corroboration). Intended for credential theft; H8 (zero benign isolations)
  is rechecked at M10.

## 2026-10-25 22:01 � v2 M10: reachable ladder (escalation) + a7 persistent + a8 composition

- Diagnosed the v1 defect precisely: `choose_action` needs 92 for isolate, the
  highest canonical floor is 90, and narrowing at 70 installs a capsule that
  blocks the 80-91 quarantining call before fusion sees it. Result: only
  allow/hold/narrow/block fired.
- Fixed with tether/escalation.py (D47): severity per identity (narrow/block 1,
  quarantine 2, isolate 3) shared across sessions of a corpus; level 1 turns a
  repeat narrow into quarantine, level 2 into isolate; decay after 25
  offense-free sessions; blocked probes deduped to one offense per session.
  Bands, floors and weights untouched.
- a7 persistent intruder (D48): three phases by session index - retry (0-4,
  full a1-style chain), slow (5-14, drip to an allowed destination so the drift
  budget latches -> a genuine `hold`), hard (15+, chain again at level 2 ->
  isolate). a8 composition (D49): every step contract-legal (asserted in a
  test), illegal only as a sequence, caught by provenance tainted-carry at 63.
  No new detector was added for either attack.
- results.json gains `ladder_usage` per corpus + total and `ladder_usage_total`
  (D50) so H4 is counted from decisions, not asserted in prose.
- Reduced-corpus sanity (20/attack, seed 7, NOT the final table): a7 rungs
  allow 45 / hold 8 / narrow 1 / quarantine 1 / isolate 8 -> H4 holds at this n.
  a8 100 % detected, 0 leak. a1 100 %/0 leak, a3 p1 0 -> p2 95, a4 p1 0 -> p2 80
  (drift timing shifts with corpus size; final n=200 in M11). benign 0 false
  alerts, utility 100 %, zero isolations (H8).
- Honest trade-off found and kept: attack-session utility drops (62.5 % at this
  n) because a repeated attacking identity is escalated; phase-B drip leaks
  ~2 records before the drift latch. Both are reported, not suppressed.
- Tests: 65 -> 76 green in 4 files (escalation policy, rung coverage, benign
  never isolated, a8 legality + catch, hard-phase exfil blocked).

## 2026-10-25 22:20 � v2 M11: evaluation v2 (CIs, ablation, determinism, honest verdicts)

- New measurement modules: tether/stats.py (Wilson 95% CI, nearest-rank
  percentile, CDF points, rate_with_ci), tether/ablation.py (leave-one-out over
  the 8 detectors via Gateway.enabled; floors follow the contract detector),
  tether/verdicts.py (H1-H9 against the frozen PREREG thresholds),
  tether/report.py (deterministic digest, MANIFEST.json, RESULTS_TABLE.md,
  generated claims block).
- results.json schema v2: per attack n + Wilson CI on detected and caught, full
  leak sample vectors (none/tether) + p90, Phase-2 CI row; latency p50/p95/p99/
  max + n + CDF + samples; per-corpus drift_trajectory; report-only
  threshold_sweep (20..95); ablation matrix. MANIFEST digest excludes only
  wall_seconds and latency_ms (stopwatch values) and contains no timestamp/path.
- verify.py: two full ablation-enabled runs -> identical results digest AND
  identical manifest hash (H6); seed-11 a3/a4 replication (H7); rewrites
  MANIFEST/RESULTS_TABLE with full verdicts and writes results/VERIFY.json.
  docs_check.py: manifest-vs-results, table byte-identity, generated claims
  block, test-count claims, local links, PREREG freeze since tag m8.
- results/ regenerated ONCE under the v2 arms (D39): seed 7, 900 benign, 100
  approved-change, 200/attack (a1-a9), 11 105 gateway decisions, 77.49 s.
  Results digest e1b8fef23abf39c5cacef25b53fd2e015da53362be8a0bb46c7a9eaca97ac9aa;
  manifest hash 0b17ec142526c4e4de1e99adf17b6b5b652b8d367bce5eded6b428b308ec622e.
- H1-H9: ALL PASS.
  H1 a1/a2 caught-before-send 100.0 % (Wilson lo 98.1); H2 0 fp/1000 incl.
  approved change, utility 100.0 %; H3 identity arm 0.0 % a1-a4 (hi 1.88) and
  100.0 % a5/a6/a9; H4 every rung counted (allow 2545, hold 577, narrow 4,
  quarantine 6, isolate 1382, block 3); H5 p95 0.873 ms (n=11105); H6 identical
  digest + manifest; H7 a3 99.5 % / a4 92.5 % at seed 7 and 99.5 % / 97.0 % at
  seed 11; H8 zero isolations on benign+approved-change; H9 a8 100 % detected
  with every step contract-legal.
- Honest findings kept, not tuned away:
  * a3/a4 are 0.0 % in Phase 1 (leak unchanged) and 99.5 %/92.5 % only with the
    Phase-2 drift budget. The primary v1-compatible `detected_pct` shows the
    miss; the Phase-2 row is reported separately.
  * a7 persistent: detected 95.0 %, caught 94.5 %; 3/200 sessions leak 3-4
    records in the low-and-slow phase before the drift latch (median 0, p90 0).
  * attack-session utility 58.8 % (benign/approved-change 100 %): repeated
    incidents on one role identity escalate quickly across separately-evaluated
    corpora. D55 states the boundary; no post-hoc code change.
  * ablation: drift removal costs 99.5/92.5 pp on a3/a4; provenance removal
    costs 1.0 pp on a8 (cumulative drift backstops after session 1); a1 shows
    defence in depth (contract and provenance each independently sufficient).
- Fuzz/invariant tests: random sessions stay inside score/action/rung bounds,
  ledger chain survives, malformed/tampered envelopes never raise or authorize,
  Wilson/percentile/CDF stay ordered, digest ignores stopwatch fields.
- Tests: 76 -> 113 green (stats/report/verdict/schema + invariants). Added
  .gitignore and untracked the 25 committed __pycache__ files.
- DECISIONS: D51 schema v2, D52 digest scope, D53 ablation mechanics, D54
  verdicts frozen, D55 escalation-across-corpora limitation, D56 docs drift is
  machine-checked. docs_check.py reports 7/7 PASS.

## 2026-10-25 22:40 - v2 M12: D3COY dashboard + nine generated exhibits

- New tether/exhibits.py (stdlib only): nine deterministic SVG renderers
  (detection/leak/cusum/ablation/ladder/latency/identity/attackmap/utility),
  an INDEX spec with title/source/unit/renderer, captions that always carry
  seed, n and unit, write_all(), and a byte-based check(). Output:
  results/exhibits/<name>.svg + results/exhibits/INDEX.json, tied to the
  results digest (e1b8fef2...).
- Rewritten dashboard.html: D3COY dark tokens (#0d0d12 / #c41e3a / #16161e /
  #3a1f25 / #e0e0e0 / #ff6b6b), serif wordmark, monospace tabular data, nine
  exhibit cards fed only by /exhibits, sticky exhibit nav, ?exhibit=<name> deep
  links with scroll + highlight, live replay stepper (prev/next/play, keyboard),
  alert JSON export, and an explicit NO MEASURED RESULTS state instead of
  placeholder numbers. Live replay is labelled as a fresh simulation, not the
  seed-7 aggregate (D58).
- API: GET /exhibits (INDEX.json) and GET /exhibits/<name>.svg with an
  allowlisted lowercase basename, rejection of separators/dot-dot/URL escapes
  before any path join, and 404 {"error": "unknown exhibit"} for everything
  else (D59). Existing routes unchanged; smoke-tested /, /results, /run,
  /exhibits and traversal forms.
- Visual QA in Chromium at 1440 px: fixed E2 strip-label/attack-name collision
  (labels removed; legend kept, left column widened), E6 130.682-vs-100 tick
  collision (max annotated at its point instead of an axis tick), E9 height and
  clipped note, and widened the E1 name column. Presentational only; results/
  was not regenerated (D57, D60).
- docs_check.py now also fails if any SVG or INDEX.json is stale or hand-edited
  (eight checks). EXHIBITS.md E1-E9 status moved PLANNED -> BUILT.
- Tests: 113 -> 126 green (+13 exhibit/API/dashboard tests: SVG well-formed +
  dark theme, numbers pulled from results, captions carry seed/n/unit, digest
  tie, attack-map coverage, caption-tamper failure, traversal rejection,
  dashboard has no hardcoded measured numbers and no external URLs).
- DECISIONS: D57 generated exhibits are byte-checked; D58 dashboard aggregate
  numbers only from /exhibits; D59 exhibit route allowlist; D60 visual QA fixes
  stay presentational.
