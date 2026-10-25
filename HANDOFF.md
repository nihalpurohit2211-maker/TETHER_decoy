# HANDOFF.md — Tether simulation (FINAL)

## Status: COMPLETE

All milestones M0–M7 are implemented, measured, and verified end to end.
45/45 unittests pass. The full evaluation (`python -m tether.evaluate --seed 7`,
~11 s) writes results/ from real measured runs. Demo (3 modes), API
(/health, /contract, /scenarios, /run, /results, /stream SSE) and the
dashboard (http://127.0.0.1:8765/) were all re-verified live this session.
Sample artifacts results/sample_alert.json and results/sample_session_log.jsonl
are genuine A1 outputs (12 ledger rows: 6 events + 6 decisions, hash-chained).

For team UI work and LLM handoff, read `TRANSFER.md` — every endpoint with
live-captured payloads, field glossaries, dashboard map, ground rules.

## Measured results (seed 7, Phase 2 enabled)

```
attack              | phase1 det% | phase2 det% | leak none | leak p1 | leak p2
--------------------+-------------+-------------+-----------+---------+--------
a1_pdf_injection    | 100.0       | 100.0       | 148       | 0       | 0
a2_tool_poisoning   | 100.0       | 100.0       | 131       | 0       | 0
a3_mimicry          |   0.0       |  99.5       |  18       | 18      | 0
a4_low_and_slow     |   0.0       |  92.5       |   2       |  2      | 0
a5_stolen_token     | 100.0       | 100.0       | 328.5     | 0       | 0
a6_delegation       | 100.0       | 100.0       | 150       | 0       | 0

benign false alerts      : 0/1000 ordinary, 0/1000 incl. legit change (both phases)
benign utility preserved : 100% (both phases)
attack-session utility   : 93.2% (loss = routine emails held while a
                           destination is drift-latched under review)
gateway latency          : p50 0.15 ms, p95 0.79 ms, max ~108 ms (first-decision
                           warmup; every later decision is sub-ms)
textgate stand-in on A1  : plain 0%, mild 100%, mimic 0% (measured lexical
                           artifact — plain text contains the purpose verb
                           "send"; deliberately NOT retuned, reported as a
                           caveat about lexical gates)
```

## Which attacks missed and why

- A3 mimicry, Phase 1: 0% detected — BY DESIGN. Every step is inside tools,
  data classes, egress allowlist and per-session ceilings, so no per-session
  detector may fire without penalizing identical benign work. It IS bounded
  (per-session ceilings cap the damage at ~18 records). The lever is the
  Phase-2 drift budget: 99.5% detected, 0 median leak.
- A4 low-and-slow, Phase 1: 0% detected — expected. A 1–3 record drip inside
  ceilings looks exactly like routine mail. Phase 2 drift budget: 92.5%
  detected, 0 median leak. The residual 7.5%: sessions whose drip volume
  stays inside the CUSUM threshold are indistinguishable from null traffic
  by design; catching them would require unacceptable false-alert rates.
- A3 Phase 2 residual 0.5% (1/200 sessions): drift stayed under h in that
  draw. Honest miss, kept (attacks are never retuned after seeing results).

## CLAIMS CHECK

| Claim | Verdict | Evidence |
|---|---|---|
| Gate latency < 5 ms | SUPPORTED | p50 0.15 ms, p95 0.79 ms; max ~108 ms is first-decision warmup (caveat) |
| Zero bytes leaked on A1/A2 | SUPPORTED | 0 median leak p1+p2, 100% caught before harmful send |
| Zero false alerts on legit_change | SUPPORTED | 0/1000 incl. change, both phases; utility 100% |
| Core work continues under containment | PARTIAL | benign 100%; attack-session utility 93.2% — while a destination is drift-latched, ALL sends there are held, including routine legit email |
| Mimicry bounded, not detected | SUPPORTED | Phase 1 0% det with 18-record ceiling; Phase 2 drift budget 99.5% |
| Low-and-slow caught | NOT SUPPORTED Phase 1 / SUPPORTED Phase 2 | 0% p1 (drip invisible per-session); 92.5% p2, 0 median leak |

## Exact commands

```
python -m unittest discover -s tests -t .          # 45/45 OK
python -m tether.evaluate --seed 7                 # writes results/ (~11 s)
python -m tether.demo --scenario a1_pdf_injection --mode tether   # also --mode none|textgate
python -m tether.api                               # then open http://127.0.0.1:8765/
python calibrate_drift.py                          # h=8 null-traffic evidence
```

Windows note: run tests via
`cmd /c "python -m unittest discover -s tests -t . 2>&1"; echo "EXIT=$LASTEXITCODE"`
(plain PowerShell shows exit 1 even on OK because unittest writes to stderr).

## Known bugs / caveats

- None open. Watch items:
  - gateway latency max ~108 ms is first-decision warmup; p95 is 0.79 ms.
  - A3 Phase-1 detection is 0% BY DESIGN (bounded, not detected).
  - The textgate tier artifact (plain 0%, mild 100%, mimic 0%) is measured,
    not tuned — it demonstrates why lexical gates fail on paraphrase.
  - The A6 delegation attack uses a fixed parent/child pair, not a
    discovery test.
  - The dashboard's "skipped" timeline state exists for poisoned steps that
    follow a blocked injection vector; it is rare in this corpus because the
    vector (pdf.read) usually executes and gets narrowed instead.

## File map

- tether_build_prompt.md — operative build spec (read first)
- PROJECT_BRIEF.md — full project context (read second)
- TODO.md — milestone checklist (all boxes checked)
- HISTORY.md — append-only checkpoint log
- DECISIONS.md — numbered design decisions and deviations (D1–D31)
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
  (parse_run_params: mode/n/seed/phase2 validation, 400 on malformed input)
- TRANSFER.md — team/LLM transfer doc: all endpoints + payloads + dashboard map
- dashboard.html — single-file dark-theme dashboard (phase1/phase2 chart,
  taint labels + detector reasons in the timeline, alert card inline)
- tests/ — unittest suite (39 tests)
- results/ — written by the evaluation CLI (measured, seed 7)
