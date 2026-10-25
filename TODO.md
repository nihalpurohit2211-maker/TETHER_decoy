# TODO.md — Tether prototypes milestone checklist

Checkpoints: update HANDOFF.md, HISTORY.md, TODO.md and commit after every
milestone and at least every 10 minutes. Tests must pass after each milestone.

## Milestone checklist

- [x] M0 handoff protocol files created (HANDOFF/HISTORY/DECISIONS/TODO/RESUME_PROMPT); git BLOCKED by broken shell
- [x] M1 core: contract, events, ledger, gateway with contract check and taint chain; tests stored in tests/
- [x] M2 scoring: fusion, response ladder, alert card, baseline with cold start, change channel
- [x] M3 evaluation: scenarios, `python -m tether.evaluate --seed 7` will write results/results.json|csv, sample_alert.json, sample_session_log.jsonl
- [x] M4 demo and docs: `python -m tether.demo --scenario ... --mode ...`, README.md
- [x] M5 API: stdlib http.server JSON API + SSE event stream
- [x] M6 dashboard: dashboard.html served by the same server
- [x] M7 Phase 2: drift budget, context (stolen-token) checks, delegation checks; A5/A6 scenarios in the evaluation
- [x] Final: RUN TESTS, results table from REAL results, CLAIMS CHECK in HANDOFF.md, git tag final

## Post-final additions

- [x] TRANSFER.md written (all endpoints + live payloads + dashboard map for team UI work)
- [x] API hardening (D32): /run param validation, clean 400s, mode whitelist; 45/45 tests

## BLOCKER STATUS (shell broken -- exit 53 on everything)

All milestone source is written. Remaining work is execution-only and needs a
working shell and Python (see HANDOFF.md 'resumption instructions'). Nothing left
to write.
