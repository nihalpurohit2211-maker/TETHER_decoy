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

from tether.alert import card_from_result
from tether.contract import load_contract
from tether.detectors import BaselineTracker, DriftBudget
from tether.harness import RunConfig, SessionResult, run_session
from tether.ledger import Ledger
from tether.sim.scenarios import ATTACK_NAMES, BENIGN_STATEMENTS, build_sessions
from tether.textgate import TextGate

PHASE1_ATTACKS = ["a1_pdf_injection", "a2_tool_poisoning", "a3_mimicry", "a4_low_and_slow"]
PHASE2_ATTACKS = PHASE1_ATTACKS + ["a5_stolen_token", "a6_delegation"]

DEFAULT_COUNTS = {
    "benign": 900,
    "legit_change": 100,
    "a1_pdf_injection": 200,
    "a2_tool_poisoning": 200,
    "a3_mimicry": 200,
    "a4_low_and_slow": 200,
    "a5_stolen_token": 200,
    "a6_delegation": 200,
}

CORE_CAVEATS = [
    "simulation only; no production traces",
    "the agent is scripted, not a real LLM agent",
    "the text gate is a simple stand-in, not an LLM judge",
    "we wrote both the attacks and the detectors",
    "attacks are never retuned after seeing results; measured misses stay misses",
    "the A6 delegation attack uses a fixed parent/child pair, not a discovery test",
]


def _drift_anchor() -> dict[str, float]:
    """Frozen anchor, pseudo-seeded a priori from the contract's implied send
    volumes; replaced only by an approved change (anti-boiling-frog)."""
    return {"mail.internal": 4000.0, "supplier-portal.example": 2500.0}


def make_config(
    mode: str, phase2: bool, gate_corpus: list[str], contract, change
) -> RunConfig:
    tracker = BaselineTracker(contract)
    gate = TextGate(gate_corpus, contract.purpose) if mode != "none" else None
    budget = DriftBudget(_drift_anchor()) if phase2 else None
    return RunConfig(
        contract=contract, tracker=tracker, gate=gate, budget=budget,
        change=change, phase2=(phase2 and mode == "tether"),
    )


def _run_plan_list(plans, mode: str, cfg: RunConfig, ledger: Ledger) -> list[SessionResult]:
    return [run_session(plan, mode, cfg, ledger) for plan in plans]


def _latency_pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, int(round(p * (len(s) - 1))))
    return round(s[idx], 3)


def evaluate(seed: int, counts: dict[str, int], phase2: bool, minimal: bool = False) -> dict:
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
    per_mode["tether_p1"] = {}
    for aid in sessions:
        # per-attack configs keep tracker + budget role-level across the corpus
        cfg1 = make_config("tether", False, BENIGN_STATEMENTS, contract, None)
        per_mode["tether_p1"][aid] = _run_plan_list(sessions[aid], "tether", cfg1, ledger)
    ledger.close()

    per_mode["tether_p2"] = per_mode["tether_p1"]
    if phase2:
        ledger = Ledger(":memory:")
        per_mode["tether_p2"] = {}
        for aid in sessions:
            cfg2 = make_config("tether", True, BENIGN_STATEMENTS, contract, None)
            per_mode["tether_p2"][aid] = _run_plan_list(sessions[aid], "tether", cfg2, ledger)
        ledger.close()

    lat = [l for atk in per_mode["tether_p2"].values() for r in atk for l in r.latencies]
    latency = {
        "p50": _latency_pct(lat, 0.50), "p95": _latency_pct(lat, 0.95), "max": _latency_pct(lat, 1.0),
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
        entry: dict = {
            "id": aid,
            "name": name,
            "covered_in_phase1": aid in PHASE1_ATTACKS,
            "detected_pct": round(100.0 * len(det1) / len(tether1), 1) if tether1 else 0.0,
            "caught_before_harmful_send_pct": round(100.0 * len(cauh1) / len(tether1), 1) if tether1 else 0.0,
            "median_steps_to_detect": float(statistics.median(steps1)) if steps1 else None,
            "records_out_none": round(float(statistics.median([r.leak_records for r in none_res])), 1)
                                if none_res else 0.0,
            "records_out_tether_median": round(float(statistics.median(leaks1)), 1) if leaks1 else 0.0,
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
            entry["phase2"] = {
                "detected_pct": round(100.0 * len(det2) / len(tether2), 1) if tether2 else 0.0,
                "caught_before_harmful_send_pct": round(100.0 * len(cauh2) / len(tether2), 1) if tether2 else 0.0,
                "records_out_tether_median": round(float(statistics.median(leaks2)), 1) if leaks2 else 0.0,
            }
        if aid == "a3_mimicry":
            entry["note"] = ties_desc["a3_mimicry"]
        attacks_out.append(entry)

    def benign_block(runs: dict[str, list[SessionResult]]) -> dict:
        benign = runs.get("benign", [])
        legit = runs.get("legit_change", [])
        all_clean = benign + legit
        flagged = sum(1 for r in all_clean if r.detected)
        executed = sum(r.legit_executed for r in all_clean)
        planned = max(1, sum(r.legit_total for r in all_clean))
        return {
            "false_alerts_per_1000_ordinary": round(1000.0 * sum(1 for r in benign if r.detected) / max(1, len(benign)), 1),
            "false_alerts_per_1000_incl_legit_change": round(1000.0 * flagged / max(1, len(all_clean)), 1),
            "utility_preserved_pct": round(100.0 * executed / planned, 1),
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

    return {
        "meta": {"seed": seed, "counts": counts, "phase2": phase2,
                 "benign_sessions": n_benign, "legit_change_sessions": n_legit},
        "attacks": attacks_out,
        "benign": benign_main,
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


def main() -> None:
    ap = argparse.ArgumentParser(description="Tether evaluation")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="results")
    ap.add_argument("--minimal", action="store_true", help="tiny corpus for smoke tests")
    ap.add_argument("--phase1-only", action="store_true", help="disable Phase 2 detectors")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    result = evaluate(seed=args.seed, counts=DEFAULT_COUNTS,
                      phase2=not args.phase1_only, minimal=args.minimal)
    with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    with open(os.path.join(args.out, "results.csv"), "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "name", "covered_in_phase1", "detected_pct",
                    "caught_before_harmful_send_pct", "median_steps_to_detect",
                    "records_out_none", "records_out_tether_median"])
        for a in result["attacks"]:
            w.writerow([a["id"], a["name"], a["covered_in_phase1"], a["detected_pct"],
                        a["caught_before_harmful_send_pct"], a["median_steps_to_detect"],
                        a["records_out_none"], a["records_out_tether_median"]])
    _write_sample_files(args.out, args.seed, phase2=not args.phase1_only)

    print("latency_ms:", result["latency_ms"], "wall_seconds:", result["wall_seconds"])
    print("wrote results/ (results.json, results.csv, sample_alert.json, sample_session_log.jsonl)")


if __name__ == "__main__":
    main()
