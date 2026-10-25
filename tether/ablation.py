"""Leave-one-out detector ablation (M11, PREREG metric 12).

Runs the full tether_p2 arm once, then once per removed detector. Nothing here
changes weights, bands or signatures: the only knob is which detectors are
allowed to report. The canonical floors follow the contract detector, because
a floor is the contract check's canonical output, not a separate signal.

Base numbers are recomputed rather than borrowed from results.json so that the
deltas are measured against the same code path.
"""
from __future__ import annotations

from tether.detectors import BaselineTracker  # noqa: F401  (import surface)
from tether.harness import run_session
from tether.identity import new_authority
from tether.ledger import Ledger

DETECTORS = [
    "contract", "provenance", "identity", "delegation",
    "baseline", "context", "drift", "intent",
]


def _run_arm(contract, sessions: dict, enabled: set[str] | None) -> dict:
    from tether.evaluate import make_config, seed_captured_replays
    from tether.sim.scenarios import BENIGN_STATEMENTS

    authority = new_authority(contract)
    seed_captured_replays(authority, sessions)
    ledger = Ledger(":memory:")
    out: dict = {}
    try:
        for aid, plans in sessions.items():
            cfg = make_config(
                "tether", True, BENIGN_STATEMENTS, contract, None,
                authority=authority,
            )
            cfg.enabled = enabled
            out[aid] = [run_session(p, "tether", cfg, ledger) for p in plans]
    finally:
        ledger.close()
    return out


def _summary(runs: dict) -> dict:
    attacks = {}
    for aid, rs in runs.items():
        if aid in ("benign", "legit_change") or not rs:
            continue
        attacks[aid] = {
            "detected_pct": round(100.0 * sum(1 for r in rs if r.detected) / len(rs), 1),
            "caught_pct": round(100.0 * sum(1 for r in rs if r.caught_all_leaks) / len(rs), 1),
            "leak_median": sorted(r.leak_records for r in rs)[len(rs) // 2],
        }
    clean = runs.get("benign", []) + runs.get("legit_change", [])
    fp = 1000.0 * sum(1 for r in clean if r.detected) / max(1, len(clean))
    return {"attacks": attacks, "false_alerts_per_1000": round(fp, 1)}


def run_ablation(contract, sessions: dict) -> dict:
    """Leave-one-out over DETECTORS. Positive delta = the detector mattered."""
    base_runs = _run_arm(contract, sessions, None)
    base = _summary(base_runs)

    rows = []
    for removed in DETECTORS:
        enabled = set(DETECTORS) - {removed}
        runs = _run_arm(contract, sessions, enabled)
        summary = _summary(runs)
        per_attack = {}
        for aid, base_stats in base["attacks"].items():
            ablated = summary["attacks"].get(aid, {})
            per_attack[aid] = {
                "caught_pct": ablated.get("caught_pct", 0.0),
                "delta_caught_pp": round(
                    base_stats["caught_pct"] - ablated.get("caught_pct", 0.0), 1
                ),
                "detected_pct": ablated.get("detected_pct", 0.0),
            }
        rows.append({
            "removed": removed,
            "attacks": per_attack,
            "false_alerts_per_1000": summary["false_alerts_per_1000"],
            "delta_false_alerts_per_1000": round(
                summary["false_alerts_per_1000"] - base["false_alerts_per_1000"], 1
            ),
        })
    return {"base": base, "rows": rows}
