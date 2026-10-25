# HANDOFF.md — Tether simulation (rewrite-at-every-checkpoint)

## Status

Bootstrap checkpoint. The five handoff files exist. The local shell is broken:
every terminal command (even `echo hello`) exits with code 53 with no output,
so `date`, `git`, `python` and test runs are all impossible right now. A
`move_to_cloud` attempt to continue in a VM was refused by the runtime ("Windows
command owner is missing. Run bun scripts/build-windows-command.ts in
freebuff-desktop."). Building continues with file tools only: source, tests and
docs are being written so the shell's first actions can be: run tests, fix what
fails, init git, commit, tag m0..m7. **Nothing has been executed yet; all
results are UNMEASURED.**

## NEXT ACTION

When a shell works (or on any healthy machine): from the repo root run
`python -m unittest discover -s tests -t . -v` against the tether package in
`tether/` and the tests in `tests/`; fix whatever fails per
tether_build_prompt.md rules (stdlib only, never tune numbers, log deviations
in DECISIONS.md), then `git init && git add -A && git commit -m "m0 bootstrap"`
and continue at M1..M7 per TODO.md.

## How to run and test

(from the repo root, Python 3.10+; Windows PowerShell or bash)

- Tests: `python -m unittest discover -s tests -t . -v`
- Evaluation: `python -m tether.evaluate --seed 7` (writes results/)
- Demo: `python -m tether.demo --scenario a1_pdf_injection --mode tether`
- API + dashboard: `python -m tether.api` then open http://127.0.0.1:8765/
- Git bootstrap (pending): `git init && git add -A && git commit -m "tether sim bootstrap" && git tag m0`

## Last test result

UNMEASURED — the shell is broken; `python` cannot run. No tests executed yet.

## Known bugs

None observed yet (nothing executable has run). Expected failure sources the
next model should check first: import consistency across
tether/{types,contract,events,ledger,textgate,detectors,fusion,response,gateway,alert}.py,
dataclass field order (non-default after default), sqlite tamper SQL, and the
SSE loop in tether/api.py.

## File map

- tether_build_prompt.md — operative build spec (read first)
- PROJECT_BRIEF.md — full project context (read second)
- TODO.md — milestone checklist with boxes
- HISTORY.md — append-only checkpoint log
- DECISIONS.md — numbered design decisions and deviations
- RESUME_PROMPT.md — paste-into-another-model resume prompt
- HANDOFF.md — this file
- tether/types.py — Context, DetectorResult, Decision, ApprovedChange
- tether/contract.py + tether/contract.json — L0 role contract (anchor)
- tether/events.py — Event dataclass
- tether/ledger.py — append-only SQLite hash-chain log + verify_chain()
- tether/textgate.py — stand-in TF-IDF text gate (not an LLM judge)
- tether/detectors.py — contract check, provenance, baseline, intent, context, delegation, drift
- tether/fusion.py — noisy-OR fusion, impact multiplier, floors, confidence
- tether/response.py — 5-rung ladder + narrowed capability set
- tether/gateway.py — single enforcement point + taint tracker
- tether/alert.py — alert card builder (fixed templates)
- tether/sim/scenarios.py — scripted plans (benign, legit_change, a1..a6)
- tether/harness.py — session executor (runs plans through modes)
- tether/evaluate.py — evaluation CLI writing results/
- tether/demo.py — colored step-by-step demo CLI
- tether/api.py — stdlib JSON API + SSE + static dashboard server
- dashboard.html — single-file dark-theme dashboard
- tests/ — unittest suite (see run command above)
- results/ — written by the evaluation CLI (unmeasured until it can run)
