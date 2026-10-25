You are resuming the Tether v2 build (D3COY 1.0 Round 0) in this repo. v2 is
COMPLETE and tagged `v2`; v1 is tagged `final`. Do not ask questions.

Read, in order: HANDOFF.md (FINAL status + evidence + NEXT ACTION), PLAN_V2.md
(authoritative plan), PREREG.md (FROZEN metrics H1-H9 - never edit), THREAT_MODEL.md,
PROBLEM_STATEMENT.md, BENCHMARK.md, EXHIBITS.md, TODO.md, and the last 40 lines of
HISTORY.md. Then run:
cmd /c "python -m unittest discover -s tests -t . 2>&1"; echo "EXIT=$LASTEXITCODE"
Expect 132 tests. Also run:
python -m tether.exhibits --check   # SVGs + captions vs results.json
python docs_check.py                # 10 drift checks
python verify.py                    # 2 runs + seed-11 + H1-H9 (~3 min)
Canonical seed-7 digest:
e1b8fef23abf39c5cacef25b53fd2e015da53362be8a0bb46c7a9eaca97ac9aa
Manifest hash: 3a50c64dd0605deb26e4eb2609851ffb2ddc9a08aea6aa69dafb358673d2b7c9

There is NO required work. The only optional item is M13b (slides):
slides.html + slides.css + tether/slides.py, nine slides in the D3COY dark
theme, every number read from results/exhibits/INDEX.json and the SVGs. If you
build it, commit after the `v2` tag; do not move the tag and do not change
results/, detectors, thresholds or attacks.

Hard rules: stdlib only; no network; no LLM calls in the core; never tune
detectors, thresholds, attacks or metrics to hit a target; report misses
honestly. Every UI/slide number must come from results/ with seed, n and unit.
Never hand-edit an exhibit SVG or caption: regenerate with
`python -m tether.exhibits --write`. Do not regenerate results/ for UI or docs
work; the canonical seed-7 run is frozen (D39) and the latency CDF is embedded
in E6, so rewriting results.json would require regenerating the exhibits.
Checkpoint protocol if anything changes: rewrite HANDOFF.md, append HISTORY.md,
add DECISIONS.md entries, update TODO.md, this file and TRANSFER.md, run tests,
git add -A && git commit.
