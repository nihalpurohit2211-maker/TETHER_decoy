"""Alert card: fixed-template explanations only, so they cannot be injected.

Explanation strings are built from fixed sentence patterns plus parameter
values (ids/scores) that the simulation itself generates — no free text from
documents or attackers is ever included.
"""
from __future__ import annotations

from tether.types import Decision


def severity(score: float) -> str:
    if score >= 92:
        return "critical"
    if score >= 80:
        return "high"
    if score >= 60:
        return "elevated"
    if score >= 30:
        return "medium"
    return "info"


def card_for(
    decision: Decision,
    untrusted_ids: list[str],
    restricted_ids: list[str],
    egress_ids: list[str],
    executed_records: float,
    executed_bytes: float,
    learned_sessions: int,
    change_id: str | None = None,
    exposure_correlated: bool = False,
) -> dict:
    counterfactual = ""
    if decision.rung != "log" and change_id:
        counterfactual = (
            f"would not have alerted had this novelty been covered by approved "
            f"change {change_id}"
        )
    elif decision.rung != "log" and exposure_correlated:
        counterfactual = (
            "novelty began after the session read untrusted content"
        )
    return {
        "schema": "tether.alert_card/1",
        "event_id": decision.event_id,
        "score": decision.score,
        "severity": severity(decision.score),
        "confidence": decision.confidence,
        "reasons": list(decision.reasons)[:3],
        "evidence": list(decision.evidence)[:3],
        "baseline_vs_now": {
            "learned_sessions": learned_sessions,
            "session_records_read": int(executed_records),
            "session_bytes_out": int(executed_bytes),
            "untrusted_event_ids": untrusted_ids,
            "restricted_event_ids": restricted_ids,
            "external_send_event_ids": egress_ids,
        },
        "action_taken": decision.action,
        "counterfactual": counterfactual,
    }


def card_from_result(result, contract, change=None, learned_sessions=0) -> dict | None:
    """Rebuild the card for the highest-score decision of one run.

    Reads only the SessionResult's (event, decision) pairs, so callers do not
    need gateway-internal state. The executed-events summary mirrors what
    Gateway.apply_effects recorded during the run.
    """
    from tether.gateway import SessionState

    state = SessionState(session=result.session)
    worst_dec: Decision | None = None
    worst_ev = None
    for ev, dec in result.decision_events:
        if worst_dec is None or dec.score > worst_dec.score:
            worst_dec, worst_ev = dec, ev
    if worst_dec is None or worst_dec.score < 30 or worst_ev is None:
        return None
    for ev, dec in result.decision_events:
        if dec.action != "allow":
            continue
        state.executed_records += ev.records
        if ev.destination:
            state.executed_bytes_out += ev.bytes
        if "RESTRICTED" in ev.labels:
            state.restricted_read = True
            state.restricted_ids.append(ev.event_id)
        if "UNTRUSTED" in ev.labels:
            state.untrusted_input = True
            state.untrusted_event_ids.append(ev.event_id)
        if "EXTERNAL_SEND" in ev.labels:
            state.off_allowlist_egress = True
            state.egress_event_ids.append(ev.event_id)
    learned = learned_sessions
    card = card_for(
        worst_dec,
        state.untrusted_event_ids,
        state.restricted_ids,
        state.egress_event_ids,
        state.executed_records,
        state.executed_bytes_out,
        learned,
        change_id=(change.change_id if change else None),
    )
    card["session"] = worst_ev.session
    card["role"] = worst_ev.role
    card["lineage"] = list(worst_ev.lineage)
    return card
