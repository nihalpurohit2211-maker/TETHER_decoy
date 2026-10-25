# HANDOFF.md — Tether simulation (rewrite-at-every-checkpoint)

## Status

All milestones M0–M7 source exists and now RUNS. The shell works (the prior
model's shell was broken; this one is healthy). 38/38 unittests pass. The full
evaluation (`python -m tether.evaluate --seed 7`) runs in ~11 s and writes
results/. Four measurement bugs were found by reading the first real numbers
and fixed (see DECISIONS D26–D29): textgate mode now screens document content
at the ingestion step only (tier metric was degenerate at 100/100/100), the
drift budget was rebuilt as a per-session standardized CUSUM on outbound
RECORD volume with h calibrated on null traffic (h=8, 0.13 null trips/1000
sessions) plus a latched alarm with modeled sponsor review (R=10 sessions,
reset unless attempted volume stays above anchor), A6's delegation envelope is
now counted as a leak, and poisoned steps now execute only when the injection
vector executed. Measured headline (seed 7): A1/A2/A5/A6 detected 100% with
zero leak; A3 mimicry 0% Phase 1 (bounded, by design) and 99.5% Phase 2; A4
low-and-slow 0% Phase 1 (expected) and 92.5% Phase 2; benign false alerts
0/1000 in both phases, benign utility 100%; attack-session utility 93.2%
(loss = routine emails held while a destination is under drift containment);
latency p50 0.14 ms, p95 0.80 ms, max ~65 ms (first-decision warmup).

## NEXT ACTION

Verify the remaining unexecuted deliverables end to end, in this order:
1. `python -m tether.demo --scenario a1_pdf_injection --mode tether` (and
   `--mode none`, `--mode textgate`) — confirm colored step log + alert card.
2. `python -m tether.api` — hit /run, /results, /stream SSE, / dashboard.
3. Read results/sample_alert.json and sample_session_log.jsonl are real A1
   artifacts. Then write the FINAL message (results table, misses, CLAIMS
   CHECK per tether_build_prompt.md) into HANDOFF.md, update TODO.md, commit
   and `git tag final`.

## How to run and test

(from the repo root, Python 3.10+; Windows PowerShell or bash)

- Tests: `python -m unittest discover -s tests -t .`
- Evaluation: `python -m tether.evaluate --seed 7` (writes results/)
- Demo: `python -m tether.demo --scenario a1_pdf_injection --mode tether`
- API + dashboard: `python -m tether.api` then open http://127.0.0.1:8765/
- Drift h calibration (null traffic): `python calibrate_drift.py`

## Last test result

38/38 pass (`python -m unittest discover -s tests -t .`), exit 0, ~0.5 s.

## Known bugs

- None open. Watch items: gateway latency max ~65 ms is first-decision
  warmup (p95 is 0.8 ms); A3 Phase-1 detection is 0% BY DESIGN (in-contract
  mimicry is bounded, not detected); the textgate tier result is a measured
  lexical artifact (plain-tier text contains the purpose verb "send" and
  scores above threshold) — do not "fix" it, report it.

## File map

- tether_build_prompt.md — operative build spec (read first)
- PROJECT_BRIEF.md — full project context (read second)
- TODO.md — milestone checklist with boxes
- HISTORY.md — append-only checkpoint log
- DECISIONS.md — numbered design decisions and deviations (D1–D29)
- RESUME_PROMPT.md — paste-into-another-model resume prompt
- HANDOFF.md — this file
- calibrate_drift.py — null-traffic calibration for the drift h (kept as
  evidence for the h=8 choice)
- tether/types.py — Context, DetectorResult, Decision, ApprovedChange
- tether/contract.py + tether/contract.json — L0 role contract (anchor)
- tether/events.py — Event dataclass
- tether/ledger.py — append-only SQLite hash-chain log + verify_chain()
- tether/textgate.py — stand-in TF-IDF text gate (not an LLM judge)
- tether/detectors.py — contract, provenance, baseline, intent, context,
  drift (CUSUM + latch + review), delegation detectors
- tether/fusion.py — noisy-OR fusion, impact multiplier, floors, confidence
- tether/response.py — 5-rung ladder + narrowed capability set
- tether/gateway.py — single enforcement point + taint tracker
- tether/alert.py — alert card builder (fixed templates)
- tether/harness.py — session executor (none / textgate / tether modes)
- tether/sim/scenarios.py — scripted plans (benign, legit_change, a1..a6)
- tether/evaluate.py — evaluation CLI writing results/
- tether/demo.py — colored step-by-step demo CLI
- tether/api.py — stdlib JSON API + SSE + static dashboard server
- dashboard.html — single-file dark-theme dashboard
- tests/ — unittest suite (38 tests)
- results/ — written by the evaluation CLI (measured, seed 7)
