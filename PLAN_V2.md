# Tether v2 — Winning Plan (D3COY 1.0, Round 0)

Written: 2026-10-25. This file is the authoritative plan for the v2 build.
The repo's HANDOFF.md remains the operational handoff; this file is the strategy.

---

## 1. Situation as I understand it

- Hackathon: D3COY 1.0 (DJS ISACA), Round 0, team "Unethically (&Gifted;)".
- PS: "Identity Drift Detection in Autonomous AI Agents".
- Round 0 submission is **slides only** (PDF/PPT format), judged on the deck —
  the prototype exists to make the deck's claims real and screenshot-ready.
- The current prototype (v1) is complete and tagged `final`: 45/45 tests,
  measured seed-7 results, API + dashboard, honest caveats.
- The user supplied the **actual current deck** (6 slides, dark red/black
  "clinical horror" theme) and wants v2 to (a) close the credibility gaps,
  (b) make the UI match that deck theme, (c) produce slide/exhibit material
  from the live system with real numbers, (d) keep the handoff docs current
  so any model can continue.

## 2. What the prototype must prove (the PS's five demands)

1. Learn normal behavior per role (not per instance).
2. Compare continuously with the declared role.
3. Detect mismatch while credentials stay valid.
4. Explain every alert with a clear risk score.
5. Restrict/isolate without disrupting legitimate work.

Every graph, slide, and scenario in v2 maps to one of these five.

## 3. Known credibility gaps in v1 (to close)

1. **Response ladder is top-heavy dead code.**
   `choose_action` needs >=92 for `isolate`, but the highest canonical floor is
   90 (restricted + egress). `quarantine` (80-91) is pre-empted by the narrowed
   capability set at 70. Net: only allow/hold/narrow/block ever fire; the
   dashboard `skipped` state is unreachable. Fix: identity-scoped escalation
   (second offense after quarantine -> isolate), reachable quarantine via
   identity+provenance+contract fusion, and scenario a7 that exercises the
   whole ladder.
2. **"Identity" is behavioral, not identity.** a5/a6 are caught by context
   heuristics. Add an identity layer: signed event envelopes (HMAC-SHA256,
   stdlib), nonce replay cache, delegation certificates, blueprint/role
   binding. New `identity` comparison arm. Honest ablation requirement:
   identity-only must score 0% on a1-a4 (injected agent signs its own
   actions) and 100% on a5/a6.
3. **Evidence is point estimates.** Add Wilson CIs, per-detector ablation,
   threshold sweeps, ladder-usage counts, leak/latency distributions, fuzz
   invariants, and a deterministic one-command `verify.py`.
4. **Only 6 attacks.** Add a7 persistent intruder (full ladder), a8 composition
   chain (each step legal, sequence violates purpose), a9 impersonation
   (role/blueprint claim mismatch). Report misses honestly.
5. **No slide artifact.** Build a slide deck (HTML -> browser print -> PDF)
   in the D3COY theme with real numbers from results/.

## 4. Visual theme spec (from the supplied deck screenshots)

Dark "clinical horror" style. Use these exact tokens:

| Token | Value | Usage |
|---|---|---|
| --bg | #0d0d12 | slide/canvas background |
| --panel | #16161e | cards |
| --panel-2 | #1c1c26 | nested cards, code blocks |
| --edge | #3a1f25 | hairline borders |
| --accent | #c41e3a | titles, pentagram, alert/block |
| --accent-soft | #d46a6a | section labels (all-caps) |
| --text | #e0e0e0 | body |
| --dim | #9a9aa6 | captions, metadata |
| --num | #ff6b6b | numeric data, event ids |
| --ok | #3fb96e | allow/clean |
| --warn | #e0a030 | hold/quarantine |

Typography: distressed/grunge serif for the D3COY wordmark and slide titles;
clean sans for body; monospace with tabular numerals for all data. Hairline
red card borders, no gradients, no glass, no emoji. Corners: DJ5 ISACA mark
left, D3COY 1.0 right, footer line with "TETHER / D3COY 1.0", year, page x/y.

## 5. Slide deck (9 slides, 16:9, print-to-PDF)

1. Title: team, college, tagline "Bounded blast radius. Fast detection. Not
   prevention.", our answer.
2. Proposed solution: valid creds pass IAM / text+LLM gates fail / structural
   consequences; 01-06 how Tether works.
3. Attack map: a1-a9 -> detector -> procurement trace -> rung.
4. Technical approach: L0-L5, detector scores, cold-start math, alert console.
5. Evidence: detection by attack with CIs, leak distribution, CUSUM chart.
6. Feasibility: ablation heatmap, ladder usage, latency CDF, tech stack.
7. Impacts: same incident without/with Tether, 5-rung binding, stakeholder value
   (incl. ISACA/audit angle: hash-chained evidence, sponsor review).
8. USP: Tether vs LLM judge vs text classifiers comparison table.
9. Roadmap + reproduce: next steps, exact commands, determinism proof.

Every number on a slide is generated from results/ (seed 7, n stated, unit
stated). No hand-typed numbers.

## 6. Milestones (each: green tests, docs updated, commit)

- M8 Research/framing: PREREG.md, THREAT_MODEL.md, problem statement, exhibit
  list. No code changes.
- M9 Identity layer: tether/identity.py (key registry, sign/verify, nonce
  cache, delegation certs), identity detector, `identity` mode arm, signed
  contract load check. Tests: tamper, replay, expired cert, forged grant,
  legit delegation no-FP.
- M10 Ladder + attacks: escalation state machine, skipped states, a7/a8/a9,
  rung-coverage test.
- M11 Evaluation v2: Wilson CIs, ablation matrix, threshold sweep, ladder
  usage, leak/latency samples, CUSUM trajectory export, results schema v2,
  verify.py, docs_check.py, fuzz invariants, MANIFEST.json.
- M12 UI v2: D3COY dark theme dashboard, 9 SVG charts, exhibit mode
  (?exhibit=name), alert export, replay stepper.
- M13 Slides + judge package:
  - M13a (required) judge package: README v2, THREAT_MODEL, EXHIBITS.md captions,
    openapi.json, BENCHMARK.md, CLAIMS CHECK v2.
  - M13b (OPTIONAL — only if time remains after M12 + M13a): slides.html/
    slides.css/tether/slides.py in the D3COY dark theme with real numbers.
    The build must not block on the slide deck.
- M14 Final: full test + evaluation, tag v2, cold-resume drill, TRANSFER.md
  final, HANDOFF FINAL.

**Priority order if time is short: M8-M12 and M13a. M13b (slides) is explicitly
optional and comes last.**

## 7. Documentation protocol (non-negotiable)

- HANDOFF.md rewritten at every milestone: status, NEXT ACTION (file +
  function), commands, last test result, known bugs, file map.
- HISTORY.md append-only, timestamped.
- DECISIONS.md numbered D33+; record alternatives rejected.
- TODO.md checkboxes for M8-M14.
- RESUME_PROMPT.md refreshed every milestone.
- TRANSFER.md kept current (endpoints, payloads, dashboard/exhibit map).
- New: PREREG.md, THREAT_MODEL.md, METRICS.md, EXHIBITS.md, BENCHMARK.md.
- docs_check.py fails if docs drift from code, results numbers, or links.
- Cold-resume drill at M10 and M14: follow only HANDOFF.md, run tests,
  reproduce the results hash, make one change in the named NEXT ACTION.

## 8. Autonomous execution rules

- Do not ask questions during the build; make the documented default choice.
- Never tune detectors, thresholds, or attacks to hit a target number.
- Pre-register metrics before measuring (PREREG.md, frozen after M8).
- Keep the repo runnable and tests green at every commit.
- Stdlib only for the simulation; no network, no LLM calls.
- Multi-agent use is allowed, but each subagent must receive the current
  HANDOFF.md + this plan and must not edit files outside its assigned scope;
  the main agent reviews and commits.
- If context is running low: run tests, update HANDOFF/RESUME, commit, print
  the summary (STOP PROTOCOL).

## 9. Defaults chosen (unless the user overrides before the build starts)

- Crypto: HMAC-SHA256 stand-in for Ed25519; logged as deviation D33.
- Theme: **D3COY dark red/black for BOTH the dashboard (M12) and the optional
  slides** (deck wins over the earlier "light" comment). Tokens in §4.
- Deck format: slides are OPTIONAL for this build — complete through M12
  first. If built: single-file HTML printed to PDF; no python-pptx.
- Number of slides: 9 (matches the current deck's 6 + evidence/attack slides).
- Keep existing attack ids a1-a6 stable; add a7-a9.
- Results are reset and regenerated once under the v2 arms.

## 10. Definition of done

- 60+ tests green; deterministic evaluation (two runs, identical MANIFEST hash).
- Every rung of the 5-rung ladder fires and is measured.
- Identity arm: 0% on a1-a4, 100% on a5/a6 (or the honest measured value).
- Dashboard exhibits generated from real results; no hand-typed numbers. The
  optional slide deck (M13b), if built, follows the same rule.
- HANDOFF.md is FINAL with results table, misses, CLAIMS CHECK, commands.
- Cold-resume drill passes.
- Tag `v2`, working tree clean.
