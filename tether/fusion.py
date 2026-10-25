"""L4 risk fusion: noisy-OR, impact multiplier, canonical floors, confidence.

Weights are the brief's starting values (contract 0.9, provenance 0.9,
delegation 0.7, baseline 0.5, context 0.7, drift 0.5, intent 0.2). Baseline's
weight arrives already scaled by maturity. Floors (D9) are canonical scores
when their condition holds; otherwise the noisy-OR * impact result is used,
adjusted by the change channel (explained x0.5, exposure-correlated x1.25).
All numbers here are starting values to calibrate, never tuned to a target.
"""
from __future__ import annotations

from tether.types import DetectorResult

BASE_WEIGHTS = {
    "contract": 0.9,
    "provenance": 0.9,
    "identity": 0.95,
    "delegation": 0.7,
    "baseline": 0.5,
    "context": 0.7,
    "drift": 0.5,
    "intent": 0.2,
}

FLOOR_RESTRICTED_EGRESS = 90.0   # restricted read + off-allowlist egress
FLOOR_RESTRICTED_CONTRACT = 70.0 # restricted-class contract violation


def impact_multiplier(restricted: bool, off_allowlist: bool) -> float:
    """m in [0.6, 1.4]: sensitivity and external exposure factors (D10)."""
    m = 1.0
    if restricted:
        m += 0.2
    if off_allowlist:
        m += 0.2
    return min(1.4, max(0.6, m))


def change_factor(status: str) -> float:
    """Legitimacy channel: explained downweights, exposure-correlated upweights."""
    if status == "explained":
        return 0.5
    if status == "exposure_correlated":
        return 1.25
    return 1.0


def fusion_score(
    results: dict[str, DetectorResult],
    restricted_now: bool,
    off_allowlist_now: bool,
    restricted_session: bool,
    egress_session: bool,
    change_status: str = "unexplained",
    floors: bool = True,
) -> float:
    """Score in [0, 100]. Canonical floors dominate when they apply.

    `floors=False` is used ONLY by the identity control arm (D41): canonical
    floors are contract policy, not identity evidence, and would otherwise let
    the identity arm "detect" a1-a4 through the restricted-class floor.
    """
    floor = 0.0
    if restricted_now and (egress_session or off_allowlist_now):
        floor = FLOOR_RESTRICTED_EGRESS
    elif restricted_now or (restricted_session and (egress_session or off_allowlist_now)):
        if restricted_now:
            floor = FLOOR_RESTRICTED_CONTRACT if not (egress_session or off_allowlist_now) else FLOOR_RESTRICTED_EGRESS
        else:
            floor = FLOOR_RESTRICTED_EGRESS

    base = 1.0
    for det, weight in BASE_WEIGHTS.items():
        res = results.get(det)
        if res is None or res.score <= 0.0:
            continue
        base *= 1.0 - min(1.0, weight * res.score)
    raw = (1.0 - base) * 100.0 * impact_multiplier(restricted_now, off_allowlist_now)
    raw *= change_factor(change_status)
    if floors and floor > 0:
        return floor  # canonical floor replaces the fused value when it applies (D9)
    return round(min(100.0, raw), 2)


def confidence(results: dict[str, DetectorResult], maturity: float) -> float:
    """Baseline maturity x signal agreement over detectors with weight > 0."""
    eligible = 0
    active = 0
    for det, weight in BASE_WEIGHTS.items():
        res = results.get(det)
        if res is None or weight <= 0.0:
            continue
        eligible += 1
        if res.score > 0.0:
            active += 1
    agreement = active / eligible if eligible else 0.0
    return round(min(1.0, maturity * agreement), 2)
