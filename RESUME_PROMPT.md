# Resume notes

Tether v2 is complete and tagged `v2`. v1 is tagged `final`.

Read `HANDOFF.md` first (status, evidence, next action), then `PLAN_V2.md`,
`PREREG.md` (frozen H1-H9, never edit), `THREAT_MODEL.md`,
`PROBLEM_STATEMENT.md`, `BENCHMARK.md`, `EXHIBITS.md`, `TODO.md`, and the last
40 lines of `HISTORY.md`. Then run:

```
cmd /c "python -m unittest discover -s tests -t . 2>&1"; echo "EXIT=$LASTEXITCODE"
```

Expect 132 tests. Also run:

```
python -m tether.exhibits --check   # SVGs + captions vs results.json
python docs_check.py                # 10 drift checks
python verify.py                    # 2 runs + seed-11 + H1-H9 (~3 min)
```

Canonical seed-7 digest:
`e1b8fef23abf39c5cacef25b53fd2e015da53362be8a0bb46c7a9eaca97ac9aa`

Manifest hash:
`3a50c64dd0605deb26e4eb2609851ffb2ddc9a08aea6aa69dafb358673d2b7c9`

No required work is left. The only optional item is M13b (slides):
`slides.html`, `slides.css` and `tether/slides.py`, nine slides in the D3COY
dark theme, with every number read from `results/exhibits/INDEX.json` and the
SVGs. If you build it, commit after the `v2` tag. Do not move the tag and do not
change `results/`, detectors, thresholds or attacks.

Rules: standard library only; no network; no LLM calls in the core; never tune
detectors, thresholds, attacks or metrics to hit a target; report misses as
measured. Every UI or slide number comes from `results/` with seed, n and unit.
Never hand-edit an exhibit SVG or caption; regenerate with
`python -m tether.exhibits --write`. Do not regenerate `results/` for UI or docs
work. The canonical seed-7 run is frozen (D39), and the latency CDF is embedded
in E6, so rewriting `results.json` would require regenerating the exhibits.

Checkpoint protocol if anything changes: rewrite `HANDOFF.md`, append
`HISTORY.md`, add `DECISIONS.md` entries, update `TODO.md`, this file and
`TRANSFER.md`, run the tests, then `git add -A && git commit`.

## UI state as of 2026-10-26 (post-v2)

`dashboard.html` uses the dark "Tactical Cyber-Brutalism" theme (obsidian
canvas, hairline borders, sharp 0px corners, emerald nominal / cyan telemetry /
crimson breach / amber warning). It has in-page charts computed at runtime from
`results.json`: corpus scorecard, containment and speed, latency empirical CDF,
threshold-sweep chart, ladder usage, ledger in-cell bars and CSV export.
`tether/exhibits.py` uses the matching dark palette, and the nine exhibit SVGs
were regenerated with `python -m tether.exhibits --write` (`--check` passes).
Only `tests/test_exhibits.py`'s colour-token list changed; the honesty checks
are intact.

Next session: serve with `python -m tether.api` (port 8765), open
`http://127.0.0.1:8765/`, and confirm 132 tests, `docs_check.py` 10/10 and
exhibits `--check` are green before touching anything.
