# Tether v2 benchmark card

What the seed-7 run measured and how to read it. The numeric block below is
generated from `results/results.json` by `python docs_check.py --fix`. A stale
or hand-edited number fails the build. Full tables are in
`results/RESULTS_TABLE.md`; figures are in `results/exhibits/`.

This is a simulation benchmark, not a production measurement. The agent is
scripted, there is no LLM in the core, and there are no production traces. The
same caveats are repeated in `results/results.json` and `THREAT_MODEL.md`.

## What was measured

- Nine attack corpora (`a1`-`a9`), each with a fixed number of sessions, run in
  the full `tether` arm. `a1`-`a6` are stable from v1; `a7`-`a9` are new in v2.
- A benign corpus and a separate approved-change corpus for the false-positive
  control. The approved-change corpus is not an attack id.
- Phase 1 is the per-session detectors, the v1-compatible primary number. Phase
  2 adds the drift budget. Both are reported, never merged.
- Detection is counted per session. `caught before harmful send` is the stricter
  outcome: the record never left the boundary.
- Latency is measured per gateway decision and reported as a distribution with
  n, not as a single average. Wilson 95 % intervals accompany every rate.
- The ablation is leave-one-out over the configured detectors. It answers "what
  changes when this one is disabled", not "is this detector necessary".

## Generated headline numbers (do not hand-edit)

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

## Reading the benchmark

- A rate without its interval is not quoted. Small differences inside
  overlapping intervals are not called improvements.
- `a3` (in-contract mimicry) and `a4` (low-and-slow) are Phase-1 misses. Their
  primary `detected_pct` is the miss itself; the Phase-2 row shows what the
  drift budget adds. The Phase-2 value is never presented as Phase 1.
- The largest ablation loss in the block is the only single-number ablation
  claim. A 0 elsewhere means "no measured loss on that corpus", not
  "unnecessary".
- Every ladder rung has a non-zero count in the generated line. `block` is an
  enforcement action counted separately from the policy rungs.
- Latency's maximum includes first-decision warm-up. The p95/p99 values are the
  operational claim. The maximum is plotted and disclosed, not trimmed.
- Attack-session utility is the containment cost of escalation across separately
  evaluated corpora (D55), not a false-positive rate. Benign and approved-change
  utility are reported separately.
- The identity arm is a control. It is blind to content attacks by design and
  strong on replay, delegation and impersonation. It does not detect
  signing-key compromise; `a5` models replay (D37/D45).

## Threats to validity

- We wrote the attacks and the detectors. The results show behavior on this
  corpus, not a guarantee against an adaptive attacker.
- The agent is scripted and the tools are simulated. No real IAM, mail, HR
  database or network egress is exercised.
- HMAC-SHA256 is a stand-in for Ed25519 (D33). Signing is tamper-evident only
  and is not a security boundary in this prototype (D44).
- Escalation sees separately evaluated corpora as one identity history (D55).
  In a mixed deployment a clean session decays the history; the corpora do not
  provide that decay.
- The contract is human-authored. Correctness of the L0 policy is assumed, not
  proven.
- There are no production traces and no external baseline. The `textgate` arm is
  a TF-IDF stand-in, not an LLM judge or a commercial DLP product.

## Reproduce

```
python -m tether.evaluate --seed 7 --ablation   # writes results/ (~78 s)
python verify.py                                # determinism + seed-11 replication
python -m tether.exhibits --write               # regenerate nine SVGs + INDEX
python -m tether.exhibits --check               # byte-compare exhibits
python docs_check.py                            # manifest/table/claims/exhibits
cmd /c "python -m unittest discover -s tests -t . 2>&1"
```

Evidence files:

- `results/results.json`: raw results
- `results/MANIFEST.json`: digest and hypothesis verdicts
- `results/VERIFY.json`: two-run determinism plus replication
- `results/RESULTS_TABLE.md`: full tables
- `results/exhibits/INDEX.json`: captions, units, n

The frozen metric definitions and thresholds are in `PREREG.md`. The plan and
decision log are in `PLAN_V2.md` and `DECISIONS.md`.
