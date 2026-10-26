# TODO.md — Tether v2 milestone checklist

Plan: `PLAN_V2.md` (authoritative strategy). Spec: `PREREG.md` (frozen metrics),
`THREAT_MODEL.md` (adversaries), `PROBLEM_STATEMENT.md` (framing).

Checkpoint after every milestone: rewrite HANDOFF.md, append HISTORY.md, add
DECISIONS.md entries, update this file + RESUME_PROMPT.md + TRANSFER.md, run
tests, `git add -A && git commit`, tag.

## v2 milestones (strict order)

- [x] M8 framing: PREREG.md (frozen), THREAT_MODEL.md, PROBLEM_STATEMENT.md,
      EXHIBITS.md exhibit list; doc drift D40 cleaned; no code changes
- [x] M9 identity layer: `tether/identity.py` (key registry, sign/verify over
      canonical JSON, nonce cache, delegation certs, role/blueprint binding),
      identity detector, `identity` arm in evaluate, signed contract load check.
      Tests: tamper, replay, expired cert, forged grant, legit delegation no-FP
- [x] M10 ladder + attacks: identity-scoped escalation state machine, reachable
      quarantine/skipped states, a7 persistent intruder, a8 composition, a9
      impersonation; rung-coverage test (H4), a8 zero-contract-violation test
- [x] M11 evaluation v2: Wilson CIs, ablation matrix, threshold sweep (reported,
      not tuned), ladder usage, leak/latency sample tails, CUSUM trajectory
      export, results schema v2, `verify.py`, `docs_check.py`,
      MANIFEST.json; results/ regenerated once under v2 arms (D39).
      Seed 7, n=200/attack: H1-H9 all PASS (H6 two-run digest + manifest hash,
      H7 seed-11 a3/a4 replication); 113/113 tests.
- [x] M12 UI v2: D3COY dark theme dashboard, 9 SVG exhibits (E1-E9),
      exhibit mode `?exhibit=name`, alert export, replay stepper; every number
      from results/ (no hand-typed values). `tether/exhibits.py` writes
      `results/exhibits/*.svg` + `INDEX.json` and `--check` byte-compares them;
      `docs_check.py` fails on stale exhibits; 126/126 tests.
- [x] M13a judge package: README v2 (CLAIMS CHECK table), EXHIBITS.md captions
      reviewed (VERIFIED), openapi.json (10 routes, 9 exhibits, checked),
      BENCHMARK.md (generated claims block), docs_check 10/10; 132/132 tests.
- [x] M14 final: verify.py two-run determinism (digest + manifest hash) and
      seed-11 replication, full tests (132), exhibits --check, docs_check 10/10,
      cold-resume drill (README wording fix recorded in HISTORY/D65), HANDOFF
      FINAL, TRANSFER final, tag `v2`
- [ ] M13b (OPTIONAL, post-v2 only): slides.html + slides.css +
      `tether/slides.py`, 9 slides, D3COY theme, numbers injected from results/

## v1 record (complete, tag `final`)

<details>
<summary>M0-M7 + post-final (all done)</summary>

- [x] M0 handoff protocol files
- [x] M1 core: contract, events, ledger, gateway, taint chain
- [x] M2 scoring: fusion, ladder, alert card, baseline, change channel
- [x] M3 evaluation: scenarios, results/ writers
- [x] M4 demo + README
- [x] M5 API: stdlib http.server + SSE
- [x] M6 dashboard: single-file dark dashboard, timeline, alert card, charts
- [x] M7 Phase 2: drift budget (CUSUM h=8), context, delegation, a5/a6
- [x] Final: 45/45 tests, measured seed-7 table, CLAIMS CHECK, tag `final`
- [x] Post-final: TRANSFER.md, API hardening (D32), dashboard label/grouping fixes

</details>

## Post-v2 UI pass (2026-10-26, visual only — no metric/result/claim changed)

- [x] dashboard.html rebuilt in the light Stitch theme; every measured figure
      read at runtime from /results, /exhibits, /contract
- [x] own in-page analytics: scorecard (phase 1/2 + Wilson CI), containment +
      speed (records out none->tether, steps to detection), latency CDF with
      p50/p95/p99/max, threshold-sweep chart (matrix behind a disclosure),
      ladder usage, ledger in-cell bars, ledger CSV export
- [x] page chrome: reveal-on-scroll, progress bar, scroll-spy, back-to-top,
      `/` focuses ledger search; all motion behind prefers-reduced-motion
- [x] narrow-screen overflow fixed (inline grid-template removed, min-width:0
      containment, 390px verified)
- [x] part 2: re-themed light -> dark "Tactical Cyber-Brutalism" (obsidian
      canvas, hairlines, sharp 0px corners, emerald/cyan/crimson/amber) in both
      dashboard.html and tether/exhibits.py; nine SVGs regenerated, --check
      byte-identical; test colour-token list updated
- [ ] optional: exhibit lightbox, M13b slides (match the console theme)

## Known doc drift to keep fixed

- [x] TODO.md stale "BLOCKER STATUS (shell broken)" removed (D40)
- [x] HANDOFF.md "tests/ (39 tests)" corrected to 45 (D40)
- [x] docs_check.py must fail on test-count and doc-vs-results drift (M11)

