# HANDOFF.md: Tether v2

## Status

Tether v2 is finished and tagged `v2`. v1 is tagged `final`. The milestones ran
in strict order: M8 framing, M9 identity layer, M10 reachable ladder plus
a7/a8/a9, M11 evaluation v2, M12 exhibits and dashboard, M13a judge package,
M14 verification and cold-resume drill. M13b (slides) was optional and was not
built; see Next action.

No required work is left. Everything below reproduces from the repository with
the standard library only, no network and no LLM calls.

## Evidence

- Canonical raw results: `results/results.json`. Seed 7, n=200 sessions per
  attack, 900 benign, 100 approved-change, 11,105 gateway decisions,
  `wall_seconds=77.49` (stopwatch, excluded from the digest).
- Full tables with Wilson 95 % CIs: `results/RESULTS_TABLE.md` (generated,
  byte-checked).
- Determinism, replication and H1-H9: `results/VERIFY.json` and
  `results/MANIFEST.json`.
  - results digest: `e1b8fef23abf39c5cacef25b53fd2e015da53362be8a0bb46c7a9eaca97ac9aa`
  - manifest hash: `3a50c64dd0605deb26e4eb2609851ffb2ddc9a08aea6aa69dafb358673d2b7c9`
  - two seed-7 runs produced the same digest and manifest hash (H6 PASS)
  - seed-11 replication: a3 99.5 % [97.22, 99.91], a4 97.0 % [93.61, 98.62]
  - H1-H9: 9 PASS, 0 FAIL
- Judge card: `BENCHMARK.md` (its numeric block is generated and enforced).
- Figures with captions, units and n: `results/exhibits/INDEX.json` plus nine
  SVGs.
- API contract: `openapi.json` (10 paths, 9 exhibit names, local server only).
- Claims audit: `README.md`, section "Claims check v2".

`MANIFEST.json` records `git_commit` as the commit at which `verify.py` last ran
(`e97b42b`, tag `m13a`); commit hashes cannot self-reference the tag commit. It
is metadata outside `results_sha256` and does not affect the digest.

## Generated measured claims (do not hand-edit)

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

## Misses and limitations

- a3 mimicry and a4 low-and-slow are Phase-1 misses: 0.0 % detected
  [0.0, 1.9] each. The Phase-2 drift budget catches them at 99.5 % and 92.5 %
  (seed 7, n=200). Never present Phase 2 as Phase 1.
- a4 still misses 7.5 % of sessions in Phase 2. a3 still leaks a median of 18
  records in Phase 1 (24 p90).
- a7 persistent intruder is partial: Phase 1 95.0 % detected and 94.5 % caught;
  Phase 2 99.0 % and 98.5 %. In the primary Phase-1 arm, 11 of 200 sessions leak
  2-4 records; after the Phase-2 latch, 3 of 200 leak 3-4. E2 plots the primary
  arm and captions that tail explicitly (D63/D65).
- Attack-session utility 58.8 % is the containment cost of identity-scoped
  escalation across separately evaluated corpora (D55). Benign and
  approved-change utility is 100.0 % [99.94, 100.0], with 0.0 false alerts
  [0.0, 0.38] per 1,000 and zero benign isolations. Do not average the two into
  one "utility" number.
- Identity layer: exactly orthogonal on this corpus (0 % on a1-a4, 100 % on
  a5/a6/a9), but it does not detect signing-key compromise. a5 models replay,
  not key theft (D37/D45). HMAC-SHA256 is a stand-in for Ed25519, and contract
  signing is tamper-evident only, not a security boundary (D33/D44).
- Latency max 130.682 ms is first-decision warm-up. The operational claim is
  p95 0.873 ms and p99 1.307 ms (n=11,105). The max is plotted and annotated on
  E6 rather than trimmed.
- Simulation only: scripted agent, no real tools, IAM, email or egress, no
  production traces. We wrote both the attacks and the detectors. The `textgate`
  arm is a TF-IDF stand-in, not an LLM judge.
- a6 uses a fixed parent/child pair; a delegation-discovery test is future work.
  Paraphrased sensitive data can slip token matching.
- The L0 contract is human-authored. Provenance assumes a gateway in the data
  path. Correctness of the policy is assumed, not proven.

## Claims check

The full evidence table is in `README.md`, section "Claims check v2". Statuses
are about this simulated seed-7 corpus, not production.

| Claim | Status |
|---|---|
| Gate latency under 5 ms | **PARTIAL**: p95/p99 pass; 130.682 ms warm-up max disclosed |
| Zero bytes leaked on a1/a2 | **SUPPORTED for records**: median 0, p90 0; not a byte count |
| Zero false alerts on approved change | **SUPPORTED**: 0.0/1,000; zero benign isolations |
| Core work continues under containment | **SUPPORTED** for legitimate work (100 %); attack utility 58.8 % is the containment cost (D55) |
| Mimicry is bounded, not detected | **SUPPORTED as stated**: Phase 1 0 %; Phase 2 99.5 % |
| Low-and-slow is caught | **PARTIAL**: Phase 2 92.5 %, 7.5 % still miss |
| Every response rung is reachable | **SUPPORTED**: all counts non-zero |
| Identity layer handles replay, bad delegation, impersonation | **SUPPORTED** on this corpus; no key-compromise claim |
| The run is deterministic | **SUPPORTED**: two runs, one digest and one manifest hash |
| Attack-session utility is 58.8 % | **DISCLOSED LIMITATION** (D55) |

## M14 cold-resume drill

Performed 2026-10-25 starting from this handoff alone (no chat context), using
only the commands below:

1. Full suite: `Ran 132 tests ... OK`, EXIT=0.
2. `python -m tether.exhibits --check`: PASS, 9 SVGs and `INDEX.json` match
   `results.json` byte for byte.
3. `python docs_check.py`: 10 passed, 0 failed.
4. Recomputed the digest from `results/results.json` with
   `tether.report.results_digest`. It matched
   `e1b8fef23abf39c5cacef25b53fd2e015da53362be8a0bb46c7a9eaca97ac9aa`
   and `MANIFEST.json` `results_sha256`.
5. Made one small named change and verified it: the README zero-leak claim now
   says the tether arm leaked a median of 0 and p90 of 0 records (and cites the
   no-defense medians 148 and 131) instead of the ambiguous "both arms' tether
   output". Docs were rechecked after the edit.

The drill exposed no hidden state and needed no undocumented command.

## Reproduce and verify

```
cmd /c "python -m unittest discover -s tests -t . 2>&1"; echo "EXIT=$LASTEXITCODE"
python -m tether.evaluate --seed 7 --ablation     # ~78 s, rewrites results/
python -m tether.exhibits --write                 # regenerate 9 SVGs + INDEX
python -m tether.exhibits --check                 # byte-compare with results/
python verify.py                                  # 2 runs + seed-11 + verdicts
python docs_check.py                              # 10 drift checks
python docs_check.py --fix                        # refresh enforced claims blocks
python -m tether.api                              # http://127.0.0.1:8765/
```

On Windows, run unittest through `cmd /c`. PowerShell can report exit 1 on OK
because unittest writes to stderr. Re-running the evaluation rewrites
`results/`; the canonical artifact is the checked-in one. `verify.py` does not
overwrite `results/results.json`, but it does rewrite `MANIFEST.json`,
`VERIFY.json` and `RESULTS_TABLE.md`.

## Last test result

2026-10-26 17:3x: `Ran 132 tests ... OK`, EXIT=0 after the post-v2 UI pass
(`dashboard.html` and `tether/exhibits.py` theme). `docs_check.py` 10/10 PASS.
Exhibits `--check` PASS (9 SVGs and `INDEX.json` byte-identical after
regeneration).

Earlier, 2026-10-25 22:58: same 132 tests OK; `docs_check.py` 10/10 PASS;
exhibits `--check` PASS; `verify.py` 9/9 hypotheses PASS with the digest and
manifest hash quoted above.

## Post-v2 UI pass (2026-10-26, uncommitted)

Visual-only work. No detector, threshold, attack, metric, result or claim
changed. `results/results.json`, `PREREG.md` and the evidence chain are
untouched; `verify.py` inputs are identical.

- `dashboard.html` was rebuilt in the light "Stitch" theme (supplied as
  `stitch_local_frontend_ui_revamp.zip`: DESIGN.md, code.html, screen.png).
  Every measured figure is read at runtime from `/results`, `/exhibits` and
  `/contract`; missing data renders the explicit `NO MEASURED RESULTS` state.
  Added in-page charts, all computed from `results.json` and never typed:
  corpus scorecard (phase 1 and phase 2 with Wilson CI whiskers), containment
  and speed (median records out none to tether, median steps to detection),
  latency empirical CDF with p50/p95/p99/max markers, threshold-sweep line chart
  with the full matrix behind a disclosure, ledger in-cell bars, and ladder
  usage by corpus. Also reveal-on-scroll, progress bar, scroll-spy, back-to-top,
  ledger filters, CSV export and `?exhibit=` deep links.
- `tether/exhibits.py`: theme tokens moved from the dark palette to the light
  one (BG/PANEL/EDGE/ACCENT/TEXT/NUM/OK/WARN), and FONT_TITLE to a sans stack.
  Phase-2 bars are amber; red is reserved for "no defense" and "block".
  Regenerated with `python -m tether.exhibits --write`; `--check` passes, so the
  exhibits are still derived byte for byte from `results.json`.
- `tests/test_exhibits.py`: only the colour-token list was re-pointed at the new
  palette. The protections that matter (no hardcoded measured numbers, no
  external URLs, `/exhibits`, `?exhibit=`, `NO MEASURED RESULTS`,
  `export alert JSON`) are unchanged and passing.

## Next action

No required work. The project is done and reproducible at `v2`. For a UI-only
continuation, keep the honesty rules: standard library only, no network, no
hardcoded measured numbers, every figure carries seed, n and unit. Keep
`python -m tether.exhibits --check` green after any exhibit change, and re-run
the 132 tests plus `docs_check.py` before committing. The only optional
technical item is M13b (slides). If it is built, use the light theme to match
the console.

## File map

- `PLAN_V2.md`: authoritative v2 plan
- `PREREG.md`: frozen metrics H1-H9 (tag m8, unchanged since)
- `THREAT_MODEL.md`: P1-P9, a1-a9, out-of-scope boundaries
- `PROBLEM_STATEMENT.md`: three drift classes, PS demands to mechanisms
- `EXHIBITS.md`: E1-E9 exhibit contract (VERIFIED)
- `BENCHMARK.md`: judge benchmark card (enforced generated claims block)
- `openapi.json`: 10-route API contract, 9 exhibit names
- `HANDOFF.md`, `HISTORY.md`, `DECISIONS.md` (D1-D65), `TODO.md`,
  `RESUME_PROMPT.md`
- `TRANSFER.md`: endpoints, payloads and dashboard map (final v2 note)
- `verify.py`: two-run determinism, seed-11 replication and verdicts
- `docs_check.py`: manifest, table, claims, exhibits, openapi, test count, links,
  PREREG
- `tether/stats.py`: Wilson CI, percentile, CDF, rate_with_ci
- `tether/report.py`: digest, MANIFEST, RESULTS_TABLE, claims block
- `tether/ablation.py`: leave-one-out detector ablation
- `tether/verdicts.py`: frozen H1-H9 verdict logic
- `tether/exhibits.py`: 9 SVG renderers, INDEX and captions, `--write`/`--check`
- `tether/identity.py` and `contract.sig.json`: signed envelopes, nonce, certs
- `tether/escalation.py`: identity-scoped severity and decay (D47)
- `tether/gateway.py`: enforcement, identity arm, escalation, `enabled` ablation
- `tether/harness.py`: session executor, envelope signing, modes
- `tether/detectors.py`: detectors, BaselineTracker, DriftBudget trajectory
- `tether/evaluate.py`: arms, CIs, leak vectors, trajectory, sweep, ablation
- `tether/sim/scenarios.py`: a1-a9 (a7 three phases, a8 composition, a9)
- `tether/demo.py`, `tether/api.py`, `dashboard.html`: demo, API, UI
- `tests/`: 132 tests in 9 files
- `results/`: frozen v2 artifacts, MANIFEST, VERIFY, RESULTS_TABLE, exhibits/
