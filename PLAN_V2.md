# Tether v2 plan (D3COY 1.0, Round 0)

Written 2026-10-25. This is the plan for the v2 build. `HANDOFF.md` is the
operational handoff; this file is strategy.

---

## 1. Starting point

- Hackathon: D3COY 1.0 (DJS ISACA), Round 0, team "Unethically (&Gifted;)".
- PS: "Identity Drift Detection in Autonomous AI Agents".
- The Round 0 submission is slides only (PDF/PPT), judged on the deck. The
  prototype exists to make the deck's claims real and screenshot-ready.
- v1 is complete and tagged `final`: 45/45 tests, measured seed-7 results, API
  and dashboard, caveats.
- The supplied deck (6 slides, dark red/black "clinical horror" theme) sets the
  visual direction. v2 has to close the credibility gaps, make the UI match the
  deck, produce slide material from the live system with real numbers, and keep
  the handoff docs current.

## 2. What the prototype must prove

The PS's five demands:

1. Learn normal behavior per role, not per instance.
2. Compare continuously with the declared role.
3. Detect mismatch while credentials stay valid.
4. Explain every alert with a clear risk score.
5. Restrict or isolate without disrupting legitimate work.

Every graph, slide and scenario in v2 maps to one of these.

## 3. Credibility gaps in v1

1. **The response ladder was top-heavy dead code.** `choose_action` needs >= 92
   for `isolate`, but the highest canonical floor is 90 (restricted plus
   egress). `quarantine` (80-91) was pre-empted by the narrowed capability set
   at 70. Only allow/hold/narrow/block ever fired, and the dashboard `skipped`
   state was unreachable. Fix: identity-scoped escalation (second offense after
   quarantine becomes isolate), a reachable quarantine via
   identity/provenance/contract fusion, and scenario a7 to exercise the whole
   ladder.
2. **"Identity" was behavioral, not identity.** a5 and a6 were caught by context
   heuristics. Add an identity layer: signed event envelopes (HMAC-SHA256,
   stdlib), nonce replay cache, delegation certificates, blueprint/role binding,
   and a new `identity` comparison arm. The honesty requirement: identity-only
   must score 0 % on a1-a4 (the injected agent signs its own actions) and 100 %
   on a5/a6.
3. **Evidence was point estimates.** Add Wilson CIs, per-detector ablation,
   threshold sweeps, ladder-usage counts, leak and latency distributions, fuzz
   invariants, and a deterministic one-command `verify.py`.
4. **Only six attacks.** Add a7 persistent intruder (full ladder), a8 composition
   chain (each step legal, sequence violates purpose), and a9 impersonation
   (role/blueprint claim mismatch). Report misses honestly.
5. **No slide artifact.** Build a slide deck (HTML, then browser print to PDF) in
   the D3COY theme with real numbers from `results/`.

## 4. Visual theme

Dark "clinical horror" style. Exact tokens:

| Token | Value | Usage |
|---|---|---|
| --bg | #0d0d12 | slide/canvas background |
| --panel | #16161e | cards |
| --panel-2 | #1c1c26 | nested cards, code blocks |
| --edge | #3a1f25 | hairline borders |
| --accent | #c41e3a | titles, pentagram, alert/block |
| --accent-soft | #d46a6a | section labels (all caps) |
| --text | #e0e0e0 | body |
| --dim | #9a9aa6 | captions, metadata |
| --num | #ff6b6b | numeric data, event ids |
| --ok | #3fb96e | allow/clean |
| --warn | #e0a030 | hold/quarantine |

Typography: distressed or grunge serif for the D3COY wordmark and slide titles;
clean sans for body; monospace with tabular numerals for data. Hairline red card
borders. No gradients, no glass, no emoji. Corners: DJS ISACA mark left, D3COY
1.0 right, footer line with "TETHER / D3COY 1.0", year, page x/y.

## 5. Deck outline

Nine slides, 16:9, print to PDF:

1. Title: team, college, tagline "Bounded blast radius. Fast detection. Not
   prevention.", our answer.
2. Proposed solution: valid creds pass IAM, text and LLM gates fail, structural
   consequences; 01-06 how Tether works.
3. Attack map: a1-a9 -> detector -> procurement trace -> rung.
4. Technical approach: L0-L5, detector scores, cold-start math, alert console.
5. Evidence: detection by attack with CIs, leak distribution, CUSUM chart.
6. Feasibility: ablation heatmap, ladder usage, latency CDF, tech stack.
7. Impacts: same incident without and with Tether, five-rung binding, stakeholder
   value, including the ISACA/audit angle (hash-chained evidence, sponsor
   review).
8. USP: Tether versus LLM judge and text classifiers.
9. Roadmap and reproduce: next steps, exact commands, determinism proof.

Every number on a slide comes from `results/` with seed, n and unit.

## 6. Milestones

Each milestone ends with green tests, updated docs and a commit.

- M8 Research and framing: `PREREG.md`, `THREAT_MODEL.md`, problem statement,
  exhibit list. No code changes.
- M9 Identity layer: `tether/identity.py` (key registry, sign/verify,
  nonce cache, delegation certs), identity detector, `identity` mode arm, signed
  contract load check. Tests: tamper, replay, expired cert, forged grant, legit
  delegation no-FP.
- M10 Ladder and attacks: escalation state machine, skipped states, a7/a8/a9,
  rung-coverage test.
- M11 Evaluation v2: Wilson CIs, ablation matrix, threshold sweep, ladder usage,
  leak and latency samples, CUSUM trajectory export, results schema v2,
  `verify.py`, `docs_check.py`, fuzz invariants, `MANIFEST.json`.
- M12 UI v2: D3COY dark theme dashboard, 9 SVG charts, exhibit mode
  (`?exhibit=name`), alert export, replay stepper.
- M13 Slides and judge package:
  - M13a (required) judge package: README v2, `THREAT_MODEL`, `EXHIBITS.md`
    captions, `openapi.json`, `BENCHMARK.md`, CLAIMS CHECK v2.
  - M13b (optional, only if time remains after M12 and M13a): `slides.html`,
    `slides.css`, `tether/slides.py` in the D3COY dark theme with real numbers.
    The build must not block on the slide deck.
- M14 Final: full test and evaluation, tag v2, cold-resume drill, `TRANSFER.md`
  final, `HANDOFF.md` final.

If time is short: M8-M12 and M13a. M13b is optional and comes last.

## 7. Documentation protocol

- `HANDOFF.md` rewritten at every milestone: status, next action (file and
  function), commands, last test result, known bugs, file map.
- `HISTORY.md` append-only and timestamped.
- `DECISIONS.md` numbered D33+, with alternatives that were rejected.
- `TODO.md` checkboxes for M8-M14.
- `RESUME_PROMPT.md` refreshed every milestone.
- `TRANSFER.md` kept current (endpoints, payloads, dashboard and exhibit map).
- New docs: `PREREG.md`, `THREAT_MODEL.md`, `METRICS.md`, `EXHIBITS.md`,
  `BENCHMARK.md`.
- `docs_check.py` fails if docs drift from code, results numbers or links.
- Cold-resume drill at M10 and M14: follow only `HANDOFF.md`, run tests,
  reproduce the results hash, and make one change in the named next action.

## 8. Execution rules

- Do not ask questions during the build; make the documented default choice.
- Never tune detectors, thresholds or attacks to hit a target number.
- Pre-register metrics before measuring (`PREREG.md`, frozen after M8).
- Keep the repo runnable and tests green at every commit.
- Standard library only for the simulation. No network, no LLM calls.
- Multi-agent use is allowed, but each subagent must receive the current
  `HANDOFF.md` and this plan, and must not edit files outside its assigned scope.
  The main agent reviews and commits.
- If context runs low: run tests, update `HANDOFF`/`RESUME`, commit, print the
  summary, stop.

## 9. Defaults

- Crypto: HMAC-SHA256 stand-in for Ed25519, logged as deviation D33.
- Theme: D3COY dark red/black for both the dashboard (M12) and the optional
  slides. Tokens in section 4.
- Deck format: slides are optional. If built, single-file HTML printed to PDF;
  no python-pptx.
- Number of slides: 9 (the current deck's 6 plus evidence and attack slides).
- Keep attack ids a1-a6 stable and add a7-a9.
- Results are reset and regenerated once under the v2 arms.

## 10. Definition of done

- 60+ tests green; deterministic evaluation (two runs, identical manifest hash).
- Every rung of the five-rung ladder fires and is measured.
- Identity arm: 0 % on a1-a4, 100 % on a5/a6, or the measured value.
- Dashboard exhibits generated from real results; no hand-typed numbers. The
  optional slide deck follows the same rule.
- `HANDOFF.md` is final with results table, misses, claims check and commands.
- Cold-resume drill passes.
- Tag `v2`, working tree clean.
