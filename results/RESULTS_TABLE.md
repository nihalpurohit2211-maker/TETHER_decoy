# RESULTS_TABLE.md — generated, do not hand-edit

Source: `results/results.json` · seed **7** · n = **200 sessions/attack**, 900 benign, 100 approved-change · unit = session (rates), records (leak), ms (latency) · Wilson 95% CI.

Regenerate with `python -m tether.evaluate --seed 7 --ablation`.

## Detection and containment, full tether arm

| id | attack | detected % | 95% CI | caught before harmful send % | 95% CI | leak median (none → tether) | leak p90 (tether) |
|---|---|---|---|---|---|---|---|
| a1_pdf_injection | pdf injection chain | 100.0 | [98.1, 100.0] | 100.0 | [98.1, 100.0] | 148.0 → 0.0 | 0.0 |
| a2_tool_poisoning | poisoned tool description | 100.0 | [98.1, 100.0] | 100.0 | [98.1, 100.0] | 131.0 → 0.0 | 0.0 |
| a3_mimicry | in-contract mimicry | 0.0 | [0.0, 1.9] | 0.0 | [0.0, 1.9] | 18.0 → 18.0 | 24.0 |
| a4_low_and_slow | low-and-slow drip | 0.0 | [0.0, 1.9] | 0.0 | [0.0, 1.9] | 2.0 → 2.0 | 3.0 |
| a5_stolen_token | stolen-token replay | 100.0 | [98.1, 100.0] | 100.0 | [98.1, 100.0] | 328.5 → 0.0 | 0.0 |
| a6_delegation | malicious delegation | 100.0 | [98.1, 100.0] | 100.0 | [98.1, 100.0] | 150.0 → 0.0 | 0.0 |
| a7_persistent | persistent intruder (repeat offense) | 95.0 | [91.0, 97.3] | 94.5 | [90.4, 96.9] | 153.5 → 0.0 | 0.0 |
| a8_composition | composition chain (every step legal) | 100.0 | [98.1, 100.0] | 100.0 | [98.1, 100.0] | 5.0 → 0.0 | 0.0 |
| a9_impersonation | identity laundering (role/blueprint mismatch) | 100.0 | [98.1, 100.0] | 100.0 | [98.1, 100.0] | 0.0 → 0.0 | 0.0 |

## Identity control arm (ablation: identity evidence only)

| id | detected % | 95% CI |
|---|---|---|
| a1_pdf_injection | 0.0 | [0.0, 1.9] |
| a2_tool_poisoning | 0.0 | [0.0, 1.9] |
| a3_mimicry | 0.0 | [0.0, 1.9] |
| a4_low_and_slow | 0.0 | [0.0, 1.9] |
| a5_stolen_token | 100.0 | [98.1, 100.0] |
| a6_delegation | 100.0 | [98.1, 100.0] |
| a7_persistent | 0.0 | [0.0, 1.9] |
| a8_composition | 0.0 | [0.0, 1.9] |
| a9_impersonation | 100.0 | [98.1, 100.0] |

Identity-only is a control, not the shipped configuration: 0% on content attacks by design, high on replay/delegation/impersonation. Key-compromise caveat: THREAT_MODEL.md §5.3.

## False alerts and utility

| metric | value | n | 95% CI |
|---|---|---|---|
| false alerts / 1000 ordinary | 0.0 | 900 | [0.0, 0.4] |
| false alerts / 1000 incl. approved change | 0.0 | 1000 | [0.0, 0.4] |
| utility preserved | 100.0% | 6588 steps | [99.9, 100.0] |
| attack-session utility | 58.8% | attack sessions, seed 7 | n/a |

## Ladder usage (all attack corpora, full arm)

| rung | count |
|---|---|
| allow | 2545 |
| hold | 577 |
| narrow | 4 |
| quarantine | 6 |
| isolate | 1382 |
| block | 3 |

## Latency

p50 0.215 ms · p95 0.873 ms · p99 1.307 ms · max 130.682 ms (n = 11105 decisions; max includes first-decision warm-up).

## Pre-registered hypotheses

| id | status | measured |
|---|---|---|
| H1 | PASS | a1_pdf_injection=100.0% (lo 98.12); a2_tool_poisoning=100.0% (lo 98.12) |
| H2 | PASS | fp/1000 incl legit=0.0; utility=100.0% |
| H3 | PASS | a1_pdf_injection=0.0% (hi 1.88); a2_tool_poisoning=0.0% (hi 1.88); a3_mimicry=0.0% (hi 1.88); a4_low_and_slow=0.0% (hi 1.88); a5_stolen_token=100.0%; a6_delegation=100.0%; a9_impersonation=100.0% |
| H4 | PASS | allow=2545, hold=577, narrow=4, quarantine=6, isolate=1382 |
| H5 | PASS | p95=0.873 ms (n=11105) |
| H6 | PASS | identical manifest hash |
| H7 | PASS | a3_mimicry seed7=99.5%; a4_low_and_slow seed7=92.5%; a3_mimicry seed11=99.5%; a4_low_and_slow seed11=97.0% |
| H8 | PASS | isolate decisions on clean corpora=0 |
| H9 | PASS | a8 detected=100.0% (steps contract-legal by test) |

## Caveats

- simulation only; no production traces
- the agent is scripted, not a real LLM agent
- the text gate is a simple stand-in, not an LLM judge
- we wrote both the attacks and the detectors
- attacks are never retuned after seeing results; measured misses stay misses
- the A6 delegation attack uses a fixed parent/child pair, not a discovery test
- measured miss or partial: in-contract mimicry detected 0.0%
- measured miss or partial: low-and-slow drip detected 0.0%
