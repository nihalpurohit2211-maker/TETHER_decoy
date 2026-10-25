"""Evaluation CLI. `python -m tether.evaluate --seed 7` writes results/.

Metrics come only from measurement; caveats always included (build prompt).
The same session corpus is replayed per mode. When Phase 2 is enabled the
tether path runs twice so Phase-1 and Phase-2 numbers are both honest.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import time
from collections import Counter

from tether.alert import card_from_result
from tether.contract import load_contract
from tether.detectors import BaselineTracker, DriftBudget
from tether.escalation import EscalationState
from tether.harness import RunConfig, SessionResult, run_session
from tether.identity import IdentityAuthority, new_authority
from tether.ledger import Ledger
from tether.sim.scenarios import ATTACK_NAMES, BENIGN_STATEMENTS, build_sessions
from tether.stats import cdf_points, percentile, rate_with_ci
from tether.textgate import TextGate

PHASE1_ATTACKS = ["a1_pdf_injection", "a2_tool_poisoning", "a3_mimicry", "a4_low_and_slow"]
PHASE2_ATTACKS = PHASE1_ATTACKS + [
    "a5_stolen_token", "a6_delegation", "a7_persistent", "a8_composition",
    "a9_impersonation",
]

DEFAULT_COUNTS = {
    "benign": 900,
    "legit_change": 100,
    "a1_pdf_injection": 200,
    "a2_tool_poisoning": 200,
    "a3_mimicry": 200,
    "a4_low_and_slow": 200,
    "a5_stolen_token": 200,
    "a6_delegation": 200,
    "a7_persistent": 200,
    "a8_composition": 200,
    "a9_impersonation": 200,
}

CORE_CAVEATS = [
    "simulation only; no production traces",
    "the agent is scripted, not a real LLM agent",
    "the text gate is a simple stand-in, not an LLM judge",
    "we wrote both the attacks and the detectors",
    "attacks are never retuned after seeing results; measured misses stay misses",
    "the A6 delegation attack uses a fixed parent/child pair, not a discovery test",
]


def _drift_anchor() -> dict[str, dict[str, float]]:
    """Frozen anchor, pseudo-seeded a priori from the deployment's stated send
    pattern for this role (one to two emails per session, roughly 30 percent
    to the portal and 70 percent internal, about one record each): per-session
    mean and spread of outbound records per destination. A real deployment
    would get these numbers from the service owner, not from live traffic;
    replaced only by an approved change (anti-boiling-frog)."""
    return {
        "mail.internal": {"mu_records": 1.0, "sigma_records": 0.7},
        "supplier-portal.example": {"mu_records": 0.5, "sigma_records": 0.6},
    }


def make_config(
    mode: str, phase2: bool, gate_corpus: list[str], contract, change,
    authority: IdentityAuthority | None = None,
) -> RunConfig:
    tracker = BaselineTracker(contract)
    gate = TextGate(gate_corpus, contract.purpose) if mode not in ("none", "identity") else None
    budget = DriftBudget(_drift_anchor()) if phase2 else None
    if authority is None and mode in ("tether", "identity"):
        authority = new_authority(contract)
    return RunConfig(
        contract=contract, tracker=tracker, gate=gate, budget=budget,
        change=change, phase2=(phase2 and mode == "tether"),
        identity=authority,
        escalation=EscalationState(),
    )


def seed_captured_replays(authority: IdentityAuthority, sessions: dict) -> None:
    """a5 replays an envelope batch that was issued earlier; mark those nonces
    as already used so freshness reflects the capture, not the run order."""
    for plan in sessions.get("a5_stolen_token", []):
        if plan.nonces:
            authority.seed_replayed(list(plan.nonces))


def seed_plan_replays(authority, plan) -> None:
    """Same, for single-session demo/API runs."""
    if authority is not None and getattr(plan, "nonces", None):
        authority.seed_replayed(list(plan.nonces))


def _run_plan_list(plans, mode: str, cfg: RunConfig, ledger: Ledger) -> list[SessionResult]:
    return [run_session(plan, mode, cfg, ledger) for plan in plans]


def _latency_pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, int(round(p * (len(s) - 1))))
    return round(s[idx], 3)


def evaluate(
    seed: int, counts: dict[str, int], phase2: bool, minimal: bool = False,
    ablation: bool = False,
) -> dict:
    t_start = time.perf_counter()
    contract = load_contract()
    counts = dict(counts)
    if minimal:
        counts.update({
            "benign": 6, "legit_change": 2, "a1_pdf_injection": 3,
            "a2_tool_poisoning": 2, "a3_mimicry": 2,
            "a4_low_and_slow": 2, "a5_stolen_token": 2, "a6_delegation": 2,
        })
    sessions = build_sessions(seed, counts)
    n_benign = counts.get("benign", 0)
    n_legit = counts.get("legit_change", 0)

    # --- no-defense and textgate runs are phase-agnostic --------------------
    per_mode: dict[str, dict[str, list[SessionResult]]] = {}
    ledger = Ledger(":memory:")
    cfg0 = make_config("none", False, BENIGN_STATEMENTS, contract, None)
    per_mode["none"] = {aid: _run_plan_list(sessions.get(aid, []), "none", cfg0, ledger)
                        for aid in sessions}
    ledger.close()
    ledger = Ledger(":memory:")
    cfgt = make_config("textgate", False, BENIGN_STATEMENTS, contract, None)
    per_mode["textgate"] = {aid: _run_plan_list(sessions.get(aid, []), "textgate", cfgt, ledger)
                            for aid in sessions}
    ledger.close()

    # --- tether runs: Phase 1 always; Phase 2 additionally when enabled ------
    ledger = Ledger(":memory:")
    auth1 = new_authority(contract)
    seed_captured_replays(auth1, sessions)
    per_mode["tether_p1"] = {}
    for aid in sessions:
        # per-attack configs keep tracker + budget role-level across the corpus
        cfg1 = make_config("tether", False, BENIGN_STATEMENTS, contract, None,
                           authority=auth1)
        per_mode["tether_p1"][aid] = _run_plan_list(sessions[aid], "tether", cfg1, ledger)
    ledger.close()

    per_mode["tether_p2"] = per_mode["tether_p1"]
    p2_cfgs: dict[str, RunConfig] = {}
    if phase2:
        ledger = Ledger(":memory:")
        auth2 = new_authority(contract)
        seed_captured_replays(auth2, sessions)
        per_mode["tether_p2"] = {}
        for aid in sessions:
            cfg2 = make_config("tether", True, BENIGN_STATEMENTS, contract, None,
                               authority=auth2)
            p2_cfgs[aid] = cfg2
            per_mode["tether_p2"][aid] = _run_plan_list(sessions[aid], "tether", cfg2, ledger)
        ledger.close()

    # --- identity control arm (D36): identity evidence ONLY, no floors ------
    ledger = Ledger(":memory:")
    auth_i = new_authority(contract)
    seed_captured_replays(auth_i, sessions)
    per_mode["identity"] = {}
    for aid in sessions:
        cfg_i = make_config("identity", False, BENIGN_STATEMENTS, contract, None,
                            authority=auth_i)
        per_mode["identity"][aid] = _run_plan_list(sessions[aid], "identity", cfg_i, ledger)
    ledger.close()

    lat = [l for atk in per_mode["tether_p2"].values() for r in atk for l in r.latencies]
    latency = {
        "p50": _latency_pct(lat, 0.50),
        "p95": _latency_pct(lat, 0.95),
        "p99": _latency_pct(lat, 0.99),
        "max": _latency_pct(lat, 1.0),
        "n": len(lat),
        "unit": "ms per gateway decision",
        "cdf": cdf_points(lat, 60),
        "samples_ms": [round(v, 3) for v in sorted(lat)],
    }

    attacks_out = []
    ties_desc = {
        "a3_mimicry": "mimicry is bounded by per-session ceilings but not detected; "
                      "the lever is the Phase-2 drift budget, not a text classifier",
    }
    for aid in PHASE2_ATTACKS:
        if aid not in sessions:
            continue
        name = ATTACK_NAMES[aid]
        none_res = per_mode["none"][aid]
        tether1 = per_mode["tether_p1"][aid]
        det1 = [r for r in tether1 if r.detected]
        cauh1 = [r for r in tether1 if r.caught_all_leaks]
        steps1 = [r.first_alert_step for r in det1 if r.first_alert_step is not None]
        leaks1 = sorted(r.leak_records for r in tether1)
        leak_none = sorted(r.leak_records for r in none_res)
        det1_rate = rate_with_ci(len(det1), len(tether1))
        cauh1_rate = rate_with_ci(len(cauh1), len(tether1))
        entry: dict = {
            "id": aid,
            "name": name,
            "covered_in_phase1": aid in PHASE1_ATTACKS,
            "n": len(tether1),
            "detected_pct": det1_rate["pct"],
            "detected_ci95": det1_rate["ci95"],
            "caught_before_harmful_send_pct": cauh1_rate["pct"],
            "caught_ci95": cauh1_rate["ci95"],
            "k_detected": det1_rate["k"],
            "k_caught": cauh1_rate["k"],
            "median_steps_to_detect": float(statistics.median(steps1)) if steps1 else None,
            "records_out_none": round(float(statistics.median(leak_none)), 1) if leak_none else 0.0,
            "records_out_tether_median": round(float(statistics.median(leaks1)), 1) if leaks1 else 0.0,
            "leak_p90_none": percentile(leak_none, 0.90),
            "leak_p90_tether": percentile(leaks1, 0.90),
            "leak_samples_none": leak_none,
            "leak_samples_tether": leaks1,
        }
        if aid == "a1_pdf_injection":
            by_tier = {}
            for tier in ("plain", "mild", "mimic"):
                tr = [r for r in per_mode["textgate"][aid] if r.tier == tier]
                by_tier[tier] = round(100.0 * sum(1 for r in tr if r.detected) / max(1, len(tr)), 1)
            entry["textgate_detected_pct_by_tier"] = by_tier
        if phase2:
            tether2 = per_mode["tether_p2"][aid]
            det2 = [r for r in tether2 if r.detected]
            cauh2 = [r for r in tether2 if r.caught_all_leaks]
            leaks2 = sorted(r.leak_records for r in tether2)
            det2_rate = rate_with_ci(len(det2), len(tether2))
            cauh2_rate = rate_with_ci(len(cauh2), len(tether2))
            entry["phase2"] = {
                "n": len(tether2),
                "detected_pct": det2_rate["pct"],
                "detected_ci95": det2_rate["ci95"],
                "caught_before_harmful_send_pct": cauh2_rate["pct"],
                "caught_ci95": cauh2_rate["ci95"],
                "k_detected": det2_rate["k"],
                "k_caught": cauh2_rate["k"],
                "records_out_tether_median": round(float(statistics.median(leaks2)), 1) if leaks2 else 0.0,
                "leak_p90_tether": percentile(leaks2, 0.90),
                "leak_samples_tether": leaks2,
            }
        if aid == "a3_mimicry":
            entry["note"] = ties_desc["a3_mimicry"]
        attacks_out.append(entry)

    def benign_block(runs: dict[str, list[SessionResult]]) -> dict:
        benign = runs.get("benign", [])
        legit = runs.get("legit_change", [])
        all_clean = benign + legit
        flagged = sum(1 for r in all_clean if r.detected)
        flagged_ordinary = sum(1 for r in benign if r.detected)
        executed = sum(r.legit_executed for r in all_clean)
        planned = max(1, sum(r.legit_total for r in all_clean))
        incl = rate_with_ci(flagged, len(all_clean))
        util = rate_with_ci(executed, planned)
        return {
            "false_alerts_per_1000_ordinary": round(1000.0 * flagged_ordinary / max(1, len(benign)), 1),
            "false_alerts_per_1000_incl_legit_change": round(1000.0 * flagged / max(1, len(all_clean)), 1),
            "utility_preserved_pct": round(100.0 * executed / planned, 1),
            "flagged_ordinary": flagged_ordinary,
            "n_ordinary": len(benign),
            "flagged_incl_legit_change": flagged,
            "n_incl_legit_change": len(all_clean),
            "false_alert_ci95_pct": incl["ci95"],
            "legit_steps_executed": executed,
            "legit_steps_planned": planned,
            "utility_ci95_pct": util["ci95"],
            "unit": "% of sessions flagged / % of legitimate planned steps executed",
        }

    benign_main = benign_block(per_mode["tether_p1"])
    if phase2:
        benign_main["phase2"] = benign_block(per_mode["tether_p2"])

    attack_sessions = []
    for aid in PHASE2_ATTACKS:
        attack_sessions.extend(per_mode["tether_p2"].get(aid, []))
    executed = sum(r.legit_executed for r in attack_sessions)
    planned = max(1, sum(r.legit_total for r in attack_sessions))

    caveats = list(CORE_CAVEATS)
    for entry in attacks_out:
        if (entry["detected_pct"] or 0.0) < 50.0:
            caveats.append(
                f"measured miss or partial: {entry['name']} detected {entry['detected_pct']}%"
            )
    if phase2:
        p2_miss = [a for a in attacks_out if a["phase2"]["detected_pct"] < 50.0]
        for a in p2_miss:
            caveats.append(f"phase-2 still misses or partially covers: {a['name']}")

    # --- identity control arm (H3): what identity evidence sees on its own ---
    identity_attacks = []
    for aid in PHASE2_ATTACKS:
        runs = per_mode["identity"].get(aid) or []
        det = [r for r in runs if r.detected]
        rate = rate_with_ci(len(det), len(runs))
        identity_attacks.append({
            "id": aid,
            "n": len(runs),
            "detected_pct": rate["pct"],
            "ci95": rate["ci95"],
            "k": rate["k"],
        })
    id_benign = benign_block(per_mode["identity"])
    identity_arm = {
        "note": ("control arm: signed envelopes, nonce freshness, delegation certs "
                 "and key->role binding only; canonical floors disabled (D36/D41)"),
        "attacks": identity_attacks,
        "false_alerts_per_1000_ordinary": id_benign["false_alerts_per_1000_ordinary"],
        "false_alerts_per_1000_incl_legit_change":
            id_benign["false_alerts_per_1000_incl_legit_change"],
    }

    # --- ladder usage (H4): a rung with count 0 is a defect, not a footnote --
    def _ladder(runs: list[SessionResult]) -> dict:
        actions: Counter = Counter()
        rungs: Counter = Counter()
        for r in runs:
            for _, dec in r.decision_events:
                actions[dec.action] += 1
                rungs[dec.rung] += 1
        return {"actions": dict(sorted(actions.items())),
                "rungs": dict(sorted(rungs.items()))}

    ladder_usage = {
        aid: _ladder(per_mode["tether_p2"].get(aid, []))
        for aid in PHASE2_ATTACKS if aid in per_mode["tether_p2"]
    }
    ladder_usage["benign"] = _ladder(per_mode["tether_p2"].get("benign", []))
    ladder_usage["legit_change"] = _ladder(per_mode["tether_p2"].get("legit_change", []))
    ladder_total = _ladder([
        r for aid in PHASE2_ATTACKS for r in per_mode["tether_p2"].get(aid, [])
    ])

    # --- cumulative-drift trajectory (EXHIBITS E3) --------------------------
    drift_trajectory: dict[str, list] = {}
    for aid, cfg in p2_cfgs.items():
        budget = cfg.budget
        if budget is not None and getattr(budget, "trajectory", None):
            drift_trajectory[aid] = budget.trajectory

    # --- threshold sweep (REPORT ONLY, never used to pick a band) -----------
    # For each candidate raw-score cutoff, how many sessions would have been
    # flagged. This is a sensitivity readout of the measured score
    # distribution. The shipped ladder still uses 30/60/80/92 plus
    # corroboration and identity-scoped escalation; the sweep does not.
    sweep_thresholds = [20, 30, 40, 50, 60, 70, 80, 90, 92, 95]
    sweep_attacks = {aid: per_mode["tether_p2"].get(aid, [])
                     for aid in PHASE2_ATTACKS}
    sweep_clean = (per_mode["tether_p2"].get("benign", [])
                   + per_mode["tether_p2"].get("legit_change", []))
    threshold_sweep = {
        "note": ("report-only sensitivity of the measured max-score distribution; "
                 "the shipped bands (30/60/80/92), corroboration rule and "
                 "identity-scoped escalation are unchanged and were not chosen "
                 "from this table"),
        "unit": "score threshold -> % of sessions with max score >= threshold",
        "rows": [
            {
                "threshold": t,
                "attacks": {
                    aid: round(100.0 * sum(1 for r in rs if r.max_score >= t)
                               / max(1, len(rs)), 1)
                    for aid, rs in sweep_attacks.items() if rs
                },
                "clean_false_alerts_per_1000": round(
                    1000.0 * sum(1 for r in sweep_clean if r.max_score >= t)
                    / max(1, len(sweep_clean)), 1
                ),
            }
            for t in sweep_thresholds
        ],
    }

    abl = None
    if ablation:
        from tether.ablation import run_ablation

        abl = run_ablation(contract, sessions)

    return {
        "meta": {"seed": seed, "counts": counts, "phase2": phase2,
                 "benign_sessions": n_benign, "legit_change_sessions": n_legit,
                 "schema_version": 2,
                 "unit_detection": "session",
                 "unit_leak": "records",
                 "unit_latency": "ms per gateway decision"},
        "attacks": attacks_out,
        "benign": benign_main,
        "identity_arm": identity_arm,
        "ladder_usage": ladder_usage,
        "ladder_usage_total": ladder_total,
        "drift_trajectory": drift_trajectory,
        "threshold_sweep": threshold_sweep,
        "ablation": abl,
        "attack_session_utility_pct": round(100.0 * executed / planned, 1),
        "latency_ms": latency,
        "wall_seconds": round(time.perf_counter() - t_start, 2),
        "caveats": caveats,
    }


def _write_sample_files(out_dir: str, seed: int, phase2: bool) -> None:
    """A real A1 alert card and its full session log from one tether run."""
    contract = load_contract()
    plans = build_sessions(seed, {"a1_pdf_injection": 1})["a1_pdf_injection"]
    plan = plans[0]
    ledger = Ledger(":memory:")
    cfg = make_config("tether", phase2, BENIGN_STATEMENTS, contract, None)
    result = run_session(plan, "tether", cfg, ledger)
    card = card_from_result(result, contract, plan.change,
                            learned_sessions=cfg.tracker.learned_sessions)
    if card is not None:
        with open(os.path.join(out_dir, "sample_alert.json"), "w", encoding="utf-8") as fh:
            json.dump(card, fh, indent=2, sort_keys=True)
    with open(os.path.join(out_dir, "sample_session_log.jsonl"), "w", encoding="utf-8") as fh:
        for row in ledger.rows_for_session(plan.session):
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    ledger.close()


def _write_csvs(out_dir: str, result: dict) -> None:
    with open(os.path.join(out_dir, "results.csv"), "w", encoding="utf-8",
              newline="") as fh:
        w = csv.writer(fh)
        w.writerow([
            "id", "name", "covered_in_phase1", "n", "detected_pct",
            "detected_ci_lo", "detected_ci_hi", "caught_before_harmful_send_pct",
            "caught_ci_lo", "caught_ci_hi", "median_steps_to_detect",
            "records_out_none", "records_out_tether_median", "leak_p90_tether",
        ])
        for a in result["attacks"]:
            det = a.get("detected_ci95") or [0.0, 0.0]
            cau = a.get("caught_ci95") or [0.0, 0.0]
            w.writerow([
                a["id"], a["name"], a["covered_in_phase1"], a.get("n", 0),
                a["detected_pct"], det[0], det[1],
                a["caught_before_harmful_send_pct"], cau[0], cau[1],
                a["median_steps_to_detect"], a["records_out_none"],
                a["records_out_tether_median"], a.get("leak_p90_tether", 0.0),
            ])

    abl = result.get("ablation")
    if not abl:
        return
    with open(os.path.join(out_dir, "ablation.csv"), "w", encoding="utf-8",
              newline="") as fh:
        ids = [a["id"] for a in result["attacks"]]
        w = csv.writer(fh)
        w.writerow(["removed_detector", "delta_false_alerts_per_1000"]
                   + [f"delta_caught_pp_{aid}" for aid in ids])
        for row in abl.get("rows", []):
            w.writerow([row["removed"], row["delta_false_alerts_per_1000"]]
                       + [row["attacks"].get(aid, {}).get("delta_caught_pp", 0.0)
                          for aid in ids])


def main() -> None:
    ap = argparse.ArgumentParser(description="Tether evaluation")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="results")
    ap.add_argument("--minimal", action="store_true", help="tiny corpus for smoke tests")
    ap.add_argument("--phase1-only", action="store_true", help="disable Phase 2 detectors")
    ap.add_argument("--ablation", action="store_true",
                    help="also run leave-one-out detector ablation (slow)")
    ap.add_argument("--no-samples", action="store_true",
                    help="skip the sample alert/session artifacts")
    args = ap.parse_args()

    from tether.report import write_manifest, write_results_table
    from tether.verdicts import evaluate_hypotheses, verdict_summary

    os.makedirs(args.out, exist_ok=True)
    result = evaluate(seed=args.seed, counts=DEFAULT_COUNTS,
                      phase2=not args.phase1_only, minimal=args.minimal,
                      ablation=args.ablation)

    # H6/H7 need the extra evidence verify.py produces; they are deferred here
    # rather than guessed. Verdicts live in MANIFEST.json / RESULTS_TABLE.md,
    # never inside results.json, so the measured digest stays stable.
    hypotheses = evaluate_hypotheses(result, replication=None, determinism=None)

    with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")
    _write_csvs(args.out, result)
    if not args.no_samples:
        _write_sample_files(args.out, args.seed, phase2=not args.phase1_only)
    manifest = write_manifest(args.out, result, hypotheses)
    table_path = write_results_table(args.out, result, hypotheses)

    p, f, d = verdict_summary(hypotheses)
    print("latency_ms:", {k: result["latency_ms"][k] for k in ("p50", "p95", "p99", "max")},
          "n:", result["latency_ms"]["n"], "wall_seconds:", result["wall_seconds"])
    print(f"hypotheses: {p} pass, {f} fail, {d} deferred "
          f"(H6/H7 need verify.py)")
    print("results digest:", manifest["results_sha256"])
    print(f"wrote {args.out}/ (results.json, results.csv, MANIFEST.json, "
          f"{os.path.basename(table_path)}, sample_alert.json, "
          f"sample_session_log.jsonl)")
    if f:
        print("FAILED hypotheses:",
              ", ".join(k for k, v in hypotheses.items() if v["status"] == "FAIL"))


if __name__ == "__main__":
    main()
