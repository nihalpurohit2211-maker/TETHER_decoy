"""One command that verifies the measured build (M11).

What it does
------------
1. Runs the evaluation TWICE at the primary seed in throwaway temp dirs and
   compares the deterministic results digest (PREREG H6). A mismatch is a build
   failure, not a finding.
2. Replicates a3/a4 at a secondary seed (PREREG H7). Seeds are never pooled.
3. Re-evaluates H1-H9 against `results/results.json` using the frozen PREREG
   thresholds, rewrites `results/MANIFEST.json` and `results/RESULTS_TABLE.md`
   with the full verdicts (results.json itself is never modified), and writes
   `results/VERIFY.json` with the determinism evidence and replication rows.
4. Prints a table and exits non-zero if determinism failed or anything crashed.

Exit code is NOT a claim that all hypotheses passed. A FAIL is a finding to
report (and to adjust the document's claims around), not a reason to tune a
detector. The summary line says how many need a claim adjustment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile

from tether.evaluate import DEFAULT_COUNTS, evaluate
from tether.report import (
    build_manifest,
    canonical_json,
    results_digest,
    write_manifest,
    write_results_table,
)
from tether.verdicts import evaluate_hypotheses, verdict_summary

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(ROOT, "results")


def _run_once(seed: int, counts: dict, phase2: bool, ablation: bool) -> dict:
    return evaluate(seed=seed, counts=counts, phase2=phase2, ablation=ablation)


def _replicate(seed: int, quick: bool = False) -> dict:
    """a3/a4 only at the replication seed. Same n per attack as primary."""
    n_a3 = 12 if quick else DEFAULT_COUNTS["a3_mimicry"]
    n_a4 = 12 if quick else DEFAULT_COUNTS["a4_low_and_slow"]
    counts = {
        "benign": 20 if quick else 200,
        "legit_change": 5 if quick else 50,
        "a3_mimicry": n_a3,
        "a4_low_and_slow": n_a4,
    }
    res = evaluate(seed=seed, counts=counts, phase2=True)
    out = {}
    for aid in ("a3_mimicry", "a4_low_and_slow"):
        row = next(a for a in res["attacks"] if a["id"] == aid)
        out[aid] = {
            "seed": seed,
            "n": row["n"],
            "detected_pct": row["phase2"]["detected_pct"],
            "ci95": row["phase2"]["detected_ci95"],
        }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="verify Tether results")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--replicate-seed", type=int, default=11)
    ap.add_argument("--quick", action="store_true",
                    help="tiny corpus smoke check (not a reportable verification)")
    ap.add_argument("--no-ablation", action="store_true",
                    help="skip the ablation matrix in the verification runs "
                         "(only if results.json was generated without it)")
    ap.add_argument("--results", default=RESULTS)
    args = ap.parse_args()

    results_json = os.path.join(args.results, "results.json")
    if not os.path.exists(results_json):
        print(f"FAIL: {results_json} does not exist; run "
              f"`python -m tether.evaluate --seed {args.seed}` first")
        return 1

    with open(results_json, "r", encoding="utf-8") as fh:
        canonical = json.load(fh)

    counts = dict(DEFAULT_COUNTS)
    if args.quick:
        counts = {"benign": 40, "legit_change": 10,
                  **{aid: 12 for aid in DEFAULT_COUNTS if aid.startswith("a")}}

    print(f"determinism: two runs at seed {args.seed}"
          f"{' (quick)' if args.quick else ''}"
          f"{' with ablation' if (not args.quick and not args.no_ablation) else ''}")
    with tempfile.TemporaryDirectory() as td:
        do_abl = (not args.quick and not args.no_ablation)
        a = _run_once(args.seed, counts, True, do_abl)
        b = _run_once(args.seed, counts, True, do_abl)
        da, db = results_digest(a), results_digest(b)
        ma, mb = build_manifest(a, None), build_manifest(b, None)
        mha = hashlib.sha256(canonical_json(ma).encode("utf-8")).hexdigest()
        mhb = hashlib.sha256(canonical_json(mb).encode("utf-8")).hexdigest()
    deterministic = da == db and mha == mhb
    print(f"  results digest run 1: {da}")
    print(f"  results digest run 2: {db}")
    print(f"  manifest hash run 1:  {mha}")
    print(f"  manifest hash run 2:  {mhb}")
    print(f"  H6 determinism: {'PASS' if deterministic else 'FAIL'}")

    print(f"replication: a3/a4 at seed {args.replicate_seed}")
    replication = _replicate(args.replicate_seed, quick=args.quick)
    for aid, row in replication.items():
        print(f"  {aid}: {row['detected_pct']}% "
              f"CI {row['ci95']} (n={row['n']}, seed={row['seed']})")

    canonical_digest = results_digest(canonical)
    print(f"canonical results digest: {canonical_digest}")
    if not args.quick and canonical_digest != da:
        print("WARN: results/results.json was produced by a different code "
              "state than this verification run. Regenerate it once with "
              "`python -m tether.evaluate --seed 7 --ablation` before shipping.")

    hypotheses = evaluate_hypotheses(
        canonical, replication=replication, determinism=deterministic
    )
    p, f, d = verdict_summary(hypotheses)

    print()
    print(f"{'id':<4} {'status':<10} measured")
    print("-" * 78)
    for hid, v in hypotheses.items():
        print(f"{hid:<4} {v['status']:<10} {v['value']}")
    print("-" * 78)
    print(f"{p} PASS, {f} FAIL, {d} DEFERRED")

    payload = {
        "seed": args.seed,
        "quick": args.quick,
        "ablation": (not args.quick and not args.no_ablation),
        "deterministic": deterministic,
        "digest_run_1": da,
        "digest_run_2": db,
        "manifest_hash_run_1": mha,
        "manifest_hash_run_2": mhb,
        "canonical_digest": canonical_digest,
        "canonical_matches_rerun": (None if args.quick else canonical_digest == da),
        "replication": replication,
        "hypotheses": hypotheses,
        "summary": {"pass": p, "fail": f, "deferred": d},
    }
    # Only a full run is allowed to rewrite the shipped manifest/table.
    if not args.quick:
        os.makedirs(args.results, exist_ok=True)
        with open(os.path.join(args.results, "VERIFY.json"), "w",
                  encoding="utf-8", newline="\n") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        # results.json is untouched; only verdict metadata is refreshed.
        write_manifest(args.results, canonical, hypotheses, root=ROOT)
        write_results_table(args.results, canonical, hypotheses)

    if not deterministic:
        print("\nBUILD FAILURE: two runs at the same seed did not hash equal.")
        return 1
    if f:
        print(f"\n{f} hypothesis/hypotheses FAILED. Report them as NOT "
              f"SUPPORTED and adjust the claims; do not retune detectors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
