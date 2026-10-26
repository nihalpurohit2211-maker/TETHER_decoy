# DECISIONS.md: design choices and deviations

Numbered, append-mostly. Reason required for each. "Deck/Brief" refers to the
slide-deck snapshot in PROJECT_BRIEF.md section 9 and PROJECT_BRIEF.md itself;
"Build prompt" is tether_build_prompt.md, the operative spec.

- D1 (layout). Build prompt says "CODE LAYOUT (tether_sim/)" with a package
  `tether/` inside. The workspace root plays the role of the tether_sim repo
  root, so the package lives at `<root>/tether/` plus `tests/` and
  `results/` at the root. Reason: keeps `python -m tether.evaluate` runnable
  from the workspace root as the build prompt demands.
- D2 (test runner). unittest, not pytest. Reason: stdlib-only guarantee and
  the environment cannot confirm pytest is installed; the build prompt allows
  either but unittest is the safe default.
- D3 (Event fields). The Event dataclass includes the fields listed in the
  build prompt plus two extras: `statement` (the agent's short rationale line
  used only by the advisory intent signal / text gate) and `carries` (list of
  resource ids an outbound payload references, so provenance can detect
  tainted payloads without string scraping). Reason: both are needed by the
  spec'd behavior and are additive.
- D4 (shared types). Context, DetectorResult, Decision and ApprovedChange
  live in tether/types.py. Reason: avoids circular imports; no behavior
  change.
- D5 (timestamp source). `date` cannot run (broken shell), so HISTORY.md
  uses approximate absolute times from the session clock. Reason: shell
  unavailable; the protocol's intent (an ordered checkpoint log) is
  preserved.
- D6 (git). `git init`, commits and tags are pending until the shell works.
  Exact commands are recorded in TODO/HANDOFF. Reason: no terminal available.
- D7 (attack ids follow the build prompt). Scenarios are named
  a1_pdf_injection, a2_tool_poisoning, a3_mimicry, a4_low_and_slow per the
  build prompt M3 list, which differs from the deck's A1..A7 snapshot
  (where A3 is stolen-token, A5 is low-and-slow). Phase 2 adds
  a5_stolen_token and a6_delegation. Reason: the build prompt is the
  operative spec; the mapping is recorded here to avoid confusion.
- D8 (scenario taint is scripted). The simulation marks the steps an
  attacker's injected instruction causes with `poisoned=True`; the taint
  tracker turns that into CARRY labels on events. This models "assume the
  injection succeeded" deterministically instead of using NLP to guess
  influence. Reason: deterministic, seedable, and it matches the brief's
  stance that text classifiers must never be the gate.
- D9 (fusion: canonical floors). When a floor condition applies (restricted
  class + off-allowlist egress, completed chain, restricted-class contract
  violation), the floor value is used as the score rather than only as a
  lower bound on an impact-multiplied noisy-OR result. Reason: with weights
  contract=0.9 and provenance=0.9 the noisy-OR times an impact multiplier
  would saturate at 100 on almost any restricted-class event, collapsing the
  60-79/80-91 rungs and contradicting the deck's own floor values (70/90/90).
  This keeps the graduated ladder meaningful. Logged as a deviation.
- D10 (impact multiplier). m = 1.0 + 0.2 (event data class restricted) +
  0.2 (destination off allowlist), clamped to [0.6, 1.4]. Reason: honors the
  brief's sensitivity/external-exposure factors with a deterministic rule.
- D11 (provenance partial alerts). Untrusted->restricted read without any
  egress does not alert on its own (provenance scores 0 for the partial);
  the contract detector already covers the restricted read. Provenance fires
  on tainted carry to external sends (1.0) or tainted carry to allowed
  destinations (0.5), and on the completed chain. Reason: avoids double
  counting the same underlying read and keeps false alarms low.
- D12 (isolation corroboration). Scores >=92 fire isolate only with
  corroboration (completed chain or a Phase-2 context-anomaly/repeat
  signal); otherwise the rung caps at quarantine and isolation is recorded
  as recommended for sponsor approval. Reason: automatically revoking a
  production identity on a single fused number contradicts the "without
  disrupting legitimate work" requirement; this is a response-policy choice
  logged as a policy choice.
- D13 (baseline learns only clean sessions). A session is learnable iff it
  finished with no decision above the log rung and no CARRY-labeled event.
  Cold start seeds pseudo-counts (count 10) for every (tool, data class)
  pair, destination and execution host implied by the contract, so day-one
  behavior inside the contract is not flagged. Maturity = k/(k+10) with a
  floor of 0.2 on the effective maturity used in fusion. Reason: matches the
  brief's cold-start requirement; floor keeps day-one protection non-zero.
- D14 (baseline feature set). Row frequencies over (tool, data class),
  destinations, execution hosts; first-seen penalties (tool 0.6, destination
  0.5, host 0.7); robust z-scores (median/MAD) on per-session records and
  bytes-out with penalty min(1, z/8) above z=4. Tool-transition surprisal is
  omitted (sim sessions are short; feature would be noise). Simplification
  logged as required by the brief ("Learned behavior is advisory").
- D15 (execution-context pseudo hosts). Contract gains an optional
  `execution_contexts` list seeding baseline host expectations (the agent's
  own fleet). Stolen-token sessions from a foreign host get caught by the
  host-novelty feature plus the Phase-2 context detector. Reason: the
  contract is the only trusted fact; declaring the fleet there is the least
  surprising place for it.
- D16 (text gate). TF-IDF cosine between the call statement and the contract
  purpose; idf from the benign statement corpus (the scripted benign templates).
  Threshold 0.10 cosine off-purpose. Threshold was picked BEFORE any run, on
  the structure of the data (benign categories and the two destinations are
  fixed strings), and whatever measured false-alarm rate comes out will be
  reported as measured. It is labeled a stand-in everywhere.
- D17 (utility metric). utility_preserved_pct = (legitimate steps executed
  as planned) / (legitimate steps planned), measured against the same seed's
  no-defense run. Quarantine's clean-instance re-queue counts a skipped
  poisoned step as skipped, legitimate steps still execute. Reason: makes
  "without disrupting legitimate work" measurable.
- D18 (records-out accounting). `leak` steps in the plans are attacker-benefit
  transfers; any executed leak step adds its records to that session's
  leak count. Per attack we report median leak records under no-defense and
  under tether, so "data at risk" is directly comparable. Reason: keeps the
  comparison direct.
- D19 (mimicry attack). a3 stays inside tools, data classes, egress and
  per-session ceilings; payloads go to supplier-portal.example, an allowlisted
  destination whose supplier account we model as attacker-controlled. Expected
  result: not detected, blast radius bounded by ceilings.
- D20 (API). Pure request handlers as plain functions plus a thin
  http.server shell, so handlers are unit-testable without sockets. One
  ThreadingHTTPServer serves JSON endpoints, SSE stream and the static
  dashboard. Reason: testable, stdlib-only, no framework needed.
- D21 (dashboard). Single static HTML file with inline CSS/JS (no external
  libraries or network fetches), SSE via EventSource, canvas bar charts.
  Reason: build prompt recommends exactly this; keeps the demo self-contained.
- D22 (no network anywhere). Every packet, token or LLM call is simulated by
  deterministic data structures; the ledger is SQLite; results files written
  to results/. Reason: build prompt hard rule.
- D23 (drift budget). CUSUM per (role, blueprint_version) against a FROZEN
  anchor (per-destination p50 bytes-out per session; pseudo-seeded). Refreshed
  only by approved change. Fires the drift detector; the detector is silent
  in Phase 1 and enabled in Phase 2. Reason: matches brief L2-6.
- D24 (delegation). Lineage check: a session owning lineage [A, B] evaluates
  tools in the intersection of A's grant (its permitted tools) and B's
  contract, plus inter-agent message taint (CARRY labels on `carries` in a
  delegation envelope). Phase 2 enables delegation attack + detector.
- D25 (results caveats). Every results.json carries the required caveat list
  plus measured misses discovered in the run, never a target.

- D26 (drift budget rebuild). The first-execution numbers exposed that the
  original DriftBudget (raw per-event bytes vs a hardcoded anchor) could
  never catch A4 (drip bytes sit below the benign anchor) and false-tripped
  on benign byte variance. Rebuilt as a per-session standardized CUSUM on
  outbound RECORD volume per destination (bytes are already bounded per
  session by the contract ceiling, so records are the exfiltration-relevant
  volume). k=0.5, h=8.0 with h calibrated on null traffic
  (calibrate_drift.py: 5->1.43, 6->0.73, 8->0.13, 10+->0.00 trips per 1000
  null sessions; chose the smallest h with margin under 1/1000). The alarm
  LATCHES and is cleared only by a modeled sponsor review after R=10
  sessions; the review keeps the latch iff attempted volume during review
  stays above anchor (z>2) - attackers keep pushing, ordinary senders do
  not. Motivation for each step is logged in HISTORY checkpoint 2.
- D27 (textgate mode semantics). Textgate mode originally gated every step's
  statement, which made textgate_detected_pct_by_tier degenerate (all
  100%). It now screens document CONTENT at the ingestion step (pdf.read)
  only and skips poisoned steps when the injection vector was held - the
  build prompt's 'assume the injection succeeded' now means: the injection
  lands iff the read executed. The measured tier result (plain 0%, mild
  100%, mimic 0%) is a lexical artifact of the stand-in (plain text shares
  the purpose verb 'send'); kept as measured.
- D28 (A6 leak accounting). The delegation envelope (150 hr_salary records
  pushed to the child agent) is an attacker-benefit transfer and is now
  marked leak=True; previously records_out_none for A6 was 0, i.e. the
  attack appeared harmless without any defense.
- D29 (injection-landing rule). Poisoned steps execute only when an
  injects-marked step executed earlier in the session (plans with no
  injection vector, e.g. A2's poisoned tool description, count as
  pre-poisoned). Applied consistently in textgate and tether modes.
- D30 (drift anchor source). The frozen anchor encodes the deployment's
  stated send pattern (1-2 emails/session, ~30% portal, ~1 record each) as
  a service owner would declare it; it is not fitted to observed traffic
  and is refreshed only by an approved change.
- D31 (ledger session attribution). Decision rows store only event_id, so
  rows_for_session() filtered them all out and the sample session log
  shipped events without decisions. Decisions are now attributed to the
  session of the event row they follow (the gateway appends them
  adjacently); regression test test_rows_for_session_includes_decisions.
- D32 (API parameter hardening, post-final). /run params are parsed by
  parse_run_params(): mode must be none|textgate|tether (an unknown mode
  previously reached the tether branch with gateway=None and crashed the
  server with a 500), malformed n/seed return 400 {"error": "..."} instead
  of an unhandled traceback, n stays clamped 1..20, phase2 accepts JSON
  bool or "true"/"false" string, and the GET path match is exact /run.
  Unknown scenario names keep their 404. TRANSFER.md documents every
  endpoint with live-captured payloads for team UI work.

## v2 decisions (M8)

- D33 (identity crypto stand-in). Identity envelopes are signed with
  HMAC-SHA256 over a canonical JSON encoding, using per-identity keys held in a
  local key registry, not Ed25519. Reason: stdlib only, no pip, no network;
  HMAC gives integrity plus key->role binding, which is all the identity arm
  needs. It does NOT give non-repudiation or HSM custody, and public-key
  verification (verify with a public key, never the secret) is impossible.
  Stated as a limitation in THREAT_MODEL.md 5.2 and on the identity exhibit.
  Format is versioned (alg="HS256") so a real Ed25519 can be swapped in later.
- D34 (pre-registration). PREREG.md is frozen at tag m8, before any v2 detector,
  attack or ladder code is written. Metrics, corpus sizes, seeds, arms and
  success thresholds (H1-H9) are fixed there. Any later change requires a
  PREREG deviation row AND a DECISIONS entry in the same commit. Reason: v1's
  metrics were chosen while building; v2 must be able to fail visibly.
- D35 (detection metric). v2 keeps v1's primary `detected_pct` (session has >=1
  decision with action != allow) so v1 and v2 tables remain comparable, and adds
  `caught_before_harmful_send_pct` (no `leak` step executed) as a stricter
  secondary. Reason: changing the primary would silently invalidate the v1
  numbers already quoted in HANDOFF/README; adding a stricter metric exposes
  the holds-on-legit-steps artifact instead of leaving it implicit.
- D36 (identity arm semantics). `identity` mode enables ONLY the identity
  detector (signatures, nonce freshness, key->role/blueprint binding, delegation
  certs). No contract, provenance, baseline, context, drift or intent. Reason:
  it is an ablation control for H3, not a shippable configuration; if it lit up
  on a1-a4 it would prove the layer is behavioural in disguise.
- D37 (a5 model). a5 is replay of captured signed envelopes (nonce reuse) from a
  foreign host, not signing-key compromise. Reason: under key compromise the
  identity arm cannot win by construction, and claiming otherwise would
  overstate the arm. The limitation is stated in THREAT_MODEL.md 5.3 and the a5
  row.
- D38 (attack id map). a1-a6 keep their v1 ids and meanings. New: a7 persistent
  intruder (full ladder), a8 composition chain (every step contract-legal), a9
  impersonation (key valid, claimed role/blueprint wrong). The approved-change
  corpus stays `legit_change` and is NOT given an a-id. Reason: PREREG and
  THREAT_MODEL reference these ids; renumbering would break v1 comparability.
  Note the brief's "A7 legitimate change" is therefore `legit_change`, not a7.
- D39 (v2 results reset). results/ is regenerated exactly once under the v2 arms
  at M11 (schema v2, seed 7). The v1 artifacts remain recoverable from git tag
  `final`; they are not copied forward, so no v1 number can leak into a v2
  exhibit. Reason: the prompt's default, plus it prevents mixed-provenance charts.
- D40 (doc drift cleanup, M8). TODO.md's "BLOCKER STATUS (shell broken)" section
  was stale (shell works; git has 8 commits) and contradicting HANDOFF.md's
  COMPLETE status; it is replaced by the M8-M14 checklist. HANDOFF.md's file map
  said "tests/ (39 tests)" while the suite is 45. Reason: recorded rather than
  silently deleted, and test-count drift becomes a docs_check case at M11.

## v2 decisions (M9)

- D41 (identity arm disables canonical floors). `fusion_score(..., floors=False)`
  is used only by the `identity` control arm. Reason: the floors are contract
  policy (`restricted read + egress -> 90`), so leaving them on would make the
  identity arm "detect" a1-a4 through the contract while its sole detector
  scored zero - a false attribution of identity capability. Measured effect:
  identity arm 0 % on a1-a4, 100 % on a5/a6/a9 (H3), full arm unchanged.
  Risk accepted: the arm is not a shippable configuration and is labelled as a
  control everywhere (PREREG D36).
- D42 (a9 moved into M9). a9 (identity laundering: procurement key, claims
  `hr_agent`/blueprint 2.0.0, performs contract-legal pricing work) is the
  acceptance test for the identity layer, so it ships with M9 rather than M10.
  a7 (persistent intruder) and a8 (composition chain) remain M10. Reason: H3
  cannot be evaluated without an impersonation case, and a9 needs no ladder
  changes. Recorded instead of quietly reordering the plan.
- D43 (identity outcome mapping declared before measurement). Fatal = 1.0
  (bad signature, unknown key, key substitution, role/blueprint mismatch,
  nonce replay, bad cert, child mismatch, grant exceeded); expired cert = 0.9;
  delegated call with no cert = 0.8; valid/no envelope = 0.0. These are policy
  numbers written before the identity arm was measured. Freshness uses a
  logical tick + in-memory nonce cache (capacity 20 000 > corpus size) so runs
  are reproducible; no wall-clock or OS entropy anywhere.
- D44 (signed contract is tamper-EVIDENT, not a security boundary). The
  sponsor key is derived from a constant in `tether/identity.py` and
  `contract.sig.json` is committed, so verification catches accidental or
  pipeline edits to `contract.json`, not an attacker with repo write access.
  Stated here and in THREAT_MODEL.md 5.2 so the scope is clear.
- D45 (a5 nonce pre-seeding). a5's envelopes are a captured batch, so
  `evaluate`/api/demo seed their nonces as already used before running. The
  alternative (letting the first replay through because the process cache was
  empty) would report 199/200 = 99.5 % for a modelling artifact, not a detector
  property. Seeding makes all 200 replays replays. Documented in THREAT_MODEL
  and PREREG section 7.
- D46 (event envelope field is additive). `Event.envelope` defaults to `{}`,
  so ledger rows, alert cards and API payloads for v1-style callers stay valid;
  `to_dict()` serialises it as JSON (no bytes in the envelope).

## v2 decisions (M10)

- D47 (identity-scoped escalation, not a lower isolate band). v1 needed >= 92
  for isolate while the highest canonical floor is 90, and narrowing at 70
  pre-empted the 80-91 quarantine band, so the ladder was top-heavy. The fix is
  history, not a moved threshold: severity (narrow/block 1, quarantine 2,
  isolate 3) accrues per identity (role+blueprint) across sessions; level 1
  turns a new narrow into quarantine, level 2 turns narrow/quarantine into
  isolate. The 30/60/80/92 bands and all fusion floors are untouched. A blocked
  probe under an active capsule counts as an offense, once per session (a
  capsule that denies three calls in a row is one offense, not three).
  History decays after 25 offense-free sessions. Containment stays SESSION-
  scoped: no role-wide credential revocation, because that would take out
  legitimate work and violate the PS's fifth demand. Accepted trade-off:
  attack-session utility drops when a corpus repeats the same attacking
  identity (reported as measured); benign utility stays 100 %.
- D48 (a7 is a three-phase scenario, by session index). v1 had no persistence.
  a7 is: retry (sessions 0-4, full a1-style chain), slow (5-14, drip to an
  allowed destination so the drift budget latches and produces a real `hold`),
  hard (15+, full chain again at escalation level 2 -> isolate). Reason: this is
  what a persistent intruder does after being narrowed, and it exercises all
  five rungs with genuine detector scores (H4). The phase boundaries are
  scenario design, declared in the docstring; they are not detector or
  threshold tuning, and no result was inspected before choosing them.
- D49 (a8 needs no new detector). The composition chain (untrusted doc ->
  pricing -> outbound packet carrying the doc) is caught by the existing
  provenance tainted-carry rule scoring 0.5 (weight 0.9). Measured fused score
  63 lands in `narrow`, so the send is not executed. No composition-specific
  detector was added: a new detector would have been a second chance to fit the
  attack. A test asserts every a8 step passes the contract check with score 0,
  which is what makes it composition rather than a contract violation (H9).
- D50 (ladder_usage in results). results.json now carries per-corpus and total
  counts of decisions by action and by rung. Reason: H4 is only meaningful if
  the rungs are counted from decisions, not asserted in prose; EXHIBITS E5 reads
  this block directly.

## v2 decisions (M11)

- D51 (results schema v2). results.json now carries, per attack: n, Wilson 95%
  CI on detection and on caught-before-harmful-send, full leak sample vectors
  (none and tether), leak p90, and the same CI fields for the Phase-2 row; plus
  latency p99/n/CDF/samples, per-corpus drift_trajectory, ladder_usage, a
  threshold_sweep, an optional ablation matrix, and an identity_arm with CIs.
  Reason: v1 reported medians and point estimates only, which hid the tail and
  made 0 %/100 % look exact. The schema is declared in PREREG section 3.
- D52 (deterministic digest scope). The MANIFEST digest covers the whole result
  payload except `wall_seconds` and `latency_ms` (a stopwatch measurement is
  real but not reproducible to the microsecond; latency keeps its own n, p99
  and warm-up caveat). MANIFEST.json contains no timestamp and no absolute path,
  so two runs at one seed produce the same manifest hash. verify.py checks both
  the payload digest and the manifest hash. Reason: H6 must be mechanical, not
  a promise.
- D53 (ablation mechanics). Leave-one-out over the eight detectors by passing an
  `enabled` set into Gateway; disabled detectors simply do not report. Fusion
  weights, bands and attack plans are untouched. Canonical floors follow the
  contract detector, because a floor is contract policy, not a separate signal -
  so removing `contract` removes the floors as well. Reason: the useful
  question is "what stops being caught if this signal is absent", and an
  ablation that quietly keeps the floors would overstate the detector.
- D54 (verdicts are code, thresholds are frozen). H1-H9 thresholds live in
  PREREG.md (frozen at tag m8) and are implemented in tether/verdicts.py.
  A FAIL changes the document's claim, never the threshold, the detector or the
  attack. verify.py prints FAILs and still exits 0 when the measurement itself
  is deterministic; a non-deterministic build is the only hard failure.
- D55 (escalation across separately-evaluated corpora: limitation).
  Corpora are evaluated separately and every attack session uses the same role
  identity, so `EscalationState` sees independent incidents as repeat offenses:
  from the third incident onward a1/a2/a8 sessions isolate on their first alert
  (198/200 each), which inflates the isolate count and drops attack-session
  utility to 58.8 % (benign/approved-change utility stays 100 %, zero benign
  isolations). In a mixed deployment a clean session decays the history after
  25 offense-free sessions, which corpora never provide. We do NOT claim the
  gateway can distinguish "same victim, new injection" from "same attacker
  returned"; that is a stated boundary, not something to retune after seeing
  the number. No code was changed after this was observed.
- D56 (docs drift is machine-checked). docs_check.py fails when: the MANIFEST
  digest disagrees with results.json; RESULTS_TABLE.md is not byte-identical to
  a fresh render; the generated claims block in HANDOFF/README is stale; a
  documented test count differs from the collected count; a local markdown link
  is broken; or PREREG.md changed after tag m8 without a "PREREG deviation:"
  line in this file. Reason: v1's docs drifted (39 vs 45 tests, stale TODO), and
  hand-copied numbers are the easiest way for a claim in the judge package to become
  false.
- D57 (exhibits are generated artifacts, not hand-drawn charts). Each of E1-E9
  is rendered by `tether/exhibits.py` from `results/results.json`; captions,
  source paths, units and n live in `results/exhibits/INDEX.json` and are
  byte-compared with `--check`. `docs_check.py` runs the same check, so editing
  an SVG or a caption fails the build even though every number was correct when
  first generated. Rejected: hand-authored SVG/HTML charts (drift, unverifiable
  provenance) and runtime charting from `/results` (a stale browser could show a
  different picture than the caption). The E6 maximum (130.682 ms) is annotated
  at its point instead of becoming an axis tick because it sits ~20 px from the
  100 ms decade label on the log axis; E2's "none"/"tether" strip labels were
  removed in favour of the existing legend after they collided with attack
  names. Both are presentation-only changes; no measurement was regenerated.
- D58 (the dashboard shows no aggregate number it did not receive from
  `/exhibits`). `dashboard.html` builds the run stamp, nav, cards, captions,
  units and n from `INDEX.json`; a missing artifact produces an explicit "NO
  MEASURED RESULTS" state with the commands to regenerate, never placeholder
  values. The live replay is labelled "live simulation output" and its request
  uses the measured seed but is not presented as the aggregate. Rejected:
  embedding a JSON snapshot in the HTML (two sources of truth) and tolerating
  missing results with zeros (indistinguishable from a real measured zero).
- D59 (exhibit routes are an allowlist, not a static file server). `GET
  /exhibits` returns `INDEX.json`; `GET /exhibits/<name>.svg` accepts only
  `^[a-z]+\.svg$`, requires the raw value to equal its basename, rejects `/`,
  `\` and `..`, and then checks the stem against `exhibits.INDEX` before joining
  the path. Unknown or malformed names return `404 {"error": "unknown exhibit"}`
  with size-independent JSON. This keeps the existing API surface intact and
  avoids making `results/` traversable. Rejected: serving `results/exhibits/`
  with `SimpleHTTPRequestHandler` (directory listing plus traversal surface).
- D60 (exhibit QA is visual, but fixes stay presentational). All nine exhibits
  were rendered in Chromium at 1440 px and inspected. Fixes: wider E1/E2 name
  columns, E2 strip-label collision removed, E6 max-tick collision removed, E9
  height trimmed and its note shortened. No detector, threshold, attack, metric
  or `results/` artifact changed for layout reasons. E2 draws all
  200 samples per arm (~281 KB) rather than subsampling, so the leak tail is
  inspectable; file size is accepted as the cost of showing the real
  distribution.
- D61 (the OpenAPI file is a checked route contract). `openapi.json` documents
  exactly the ten paths the server exposes (`/`, `/dashboard`, `/health`,
  `/contract`, `/scenarios`, `/run` GET+POST, `/stream`, `/results`,
  `/exhibits`, `/exhibits/{name}.svg`), only local server URLs, and exactly the
  nine exhibit names from `tether.exhibits.INDEX`. `docs_check.py` fails on path
  drift or an enum mismatch, and `tests/test_openapi.py` guards the same contract
  (plus no external `$ref`). Rejected: prose-only endpoint docs (already drifted
  from the v1 dashboard) and generating the spec into the server (the spec is
  static, the route set is small).
- D62 (the benchmark headline reuses the generated claims block). Rather than a
  second hand-written table, `BENCHMARK.md` embeds the same block that
  `docs_check.py --fix` writes into HANDOFF/README, extended with the latency
  max and the single largest ablation loss. The block is the only numeric copy;
  the rest of BENCHMARK.md is methodology, limitations and
  pointers to `RESULTS_TABLE.md`/exhibits. Rejected: a separate benchmark table
  renderer (duplicate data path, another drift surface) and prose-only numbers
  (exactly what v1 did wrong).
- D63 (exhibit captions were reviewed, not just generated). At M13a every
  caption was read against the EXHIBITS rules: seed/n/unit are enforced by
  `--check`; a3/a4 misses are called misses; the E2 caption now prints how many
  a7 sessions leak and the maximum in the plotted arm (11/200, max 4, primary
  Phase 1; 3/200 after the Phase-2 latch) instead of only median/p90,
  because median 0 + p90 0 alone would hide the real tail; the identity caption
  states the key-compromise limitation and collapses equal ranges to "all 0.0 %"
  / "all 100.0 %". Status moved BUILT -> VERIFIED. No measurement was
  regenerated.
- D64 (CLAIMS CHECK v2 is statused, not promotional). The README table maps each
  claim to evidence and marks it SUPPORTED, PARTIAL, or DISCLOSED LIMITATION.
  "Gate latency under 5 ms" is PARTIAL: true at p95/p99, false for the
  130.682 ms warm-up maximum. "Zero bytes leaked" is SUPPORTED for records only,
  because the harness measures records, not bytes. "Low-and-slow is caught" is
  PARTIAL because Phase 2 still misses 7.5 %. Attack-session utility 58.8 % is
  disclosed as containment cost (D55), never averaged with benign utility.
- D65 (M14 cold-resume drill, and an arm-label correction). The drill started
  from HANDOFF.md alone: 132/132 tests, exhibits `--check` PASS, docs_check
  10/10, digest `e1b8fef2...ac9aa` matched `MANIFEST.results_sha256`; one named
  change was then made (README's zero-leak row now names the tether arm and the
  148/131 no-defense medians). The drill also caught an arm confusion in the
  M13a prose: E2 plots `leak_samples_tether` from the **primary Phase-1** arm,
  where a7 leaks in 11/200 sessions (2-4 records, max 4). The 3/200 figure is
  the Phase-2 arm. The rendered caption was already correct; D63 and the
  M11/M13a history lines (which did not name the arm) were clarified, not the
  exhibit. This is a documentation fix:
  no detector, threshold, attack, metric or `results/` artifact changed, and
  the digest is unchanged.

- D66 (post-v2 UI pass, part 2: dark re-theme). The dashboard and the nine
  exhibit SVGs were re-themed from the light "Stitch" palette to the dark
  "Tactical Cyber-Brutalism" palette in the second supplied reference doc
  (DESIGN.md: obsidian canvas, hairline borders, sharp 0px corners, emerald
  nominal / cyan telemetry / crimson breach / amber warning). Both
  `dashboard.html` `:root` and the `tether/exhibits.py` palette constants were
  changed together and the exhibits regenerated with `--write` so `--check`
  stays byte-identical. The reference `code.html` pulls Tailwind from a CDN;
  that was deliberately not copied - the dashboard remains one self-contained
  file with no external fonts, scripts or images. Only
  `tests/test_exhibits.py`'s colour-token list was re-pointed; all honesty
  checks (runtime-sourced numbers, no hardcoded measured values, no external
  URLs, empty state, `?exhibit=`, CSV export, alert-JSON export) are unchanged
  and passing. Visual-only: no detector, threshold, attack, metric, result or
  claim changed, and the seed-7 results digest is unchanged.