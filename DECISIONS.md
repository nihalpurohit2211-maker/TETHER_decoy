# DECISIONS.md — every design choice and every deviation

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
  unavailable; the protocol's intent (ordered, honest checkpoint log) is
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
  logged for honesty.
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
  under tether, so "data at risk" is directly comparable. Reason: honest
  comparable metric.
- D19 (mimicry attack). a3 stays inside tools, data classes, egress and
  per-session ceilings; payloads go to supplier-portal.example, an allowlisted
  destination whose supplier account we model as attacker-controlled. Expected
  honest result: not detected, blast radius bounded by ceilings.
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
- D25 (results caveats). Every results.json carries the required hardcoded
  honesty set plus measured misses discovered in the run, never a target.

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
  `caught_before_harmful_send_pct` (no `leak` step executed) as the honest
  secondary. Reason: changing the primary would silently invalidate the v1
  numbers already quoted in HANDOFF/README; adding a stricter metric exposes
  the holds-on-legit-steps artifact instead of hiding it.
- D36 (identity arm semantics). `identity` mode enables ONLY the identity
  detector (signatures, nonce freshness, key->role/blueprint binding, delegation
  certs). No contract, provenance, baseline, context, drift or intent. Reason:
  it is an ablation control for H3, not a shippable configuration; if it lit up
  on a1-a4 it would prove the layer is behavioural in disguise.
- D37 (a5 model). a5 is replay of captured signed envelopes (nonce reuse) from a
  foreign host, not signing-key compromise. Reason: under key compromise the
  identity arm cannot win by construction, and pretending otherwise would be
  dishonest. The limitation is stated in THREAT_MODEL.md 5.3 and the a5 row.
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
