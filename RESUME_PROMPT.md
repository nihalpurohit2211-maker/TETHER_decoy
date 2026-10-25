You are continuing the Tether v2 build (D3COY 1.0 Round 0) in this repo.
Do not ask questions. Read, in order: PLAN_V2.md (authoritative plan), HANDOFF.md
(status + NEXT ACTION), PREREG.md (FROZEN metrics H1-H9 — never edit silently),
THREAT_MODEL.md, PROBLEM_STATEMENT.md, TODO.md, and the last 40 lines of
HISTORY.md. Then run:
cmd /c "python -m unittest discover -s tests -t . 2>&1"; echo "EXIT=$LASTEXITCODE"
Expect the count stated in HANDOFF.md. Continue from NEXT ACTION only; do not
redo finished milestones. v2 landed: M8 framing, M9 identity layer, M10 ladder +
a7/a8/a9, M11 evaluation v2 (seed 7, n=200/attack, H1-H9 all PASS, results/ frozen).
The current target is M12 (D3COY dashboard + nine generated exhibits), then
M13a (judge docs), then M14 (final). M13b (slides) is optional and only after
M12+M13a.

Before committing a milestone, also run:
python verify.py            # determinism + seed-11 replication + verdicts
python docs_check.py --fix  # regenerate the claims block, then check
Follow the checkpoint protocol after every milestone: rewrite HANDOFF.md, append
HISTORY.md, add DECISIONS.md entries, update TODO.md, RESUME_PROMPT.md and
TRANSFER.md, run tests, git add -A && git commit, tag.
Hard rules: stdlib only; no network; no LLM calls in the core; never tune
detectors, thresholds, attacks or metrics to hit a target; report misses
honestly. Every UI/slide number must come from results/ with seed, n and unit.
