"""L1 event gateway: the single enforcement point. Owns the taint tracker.

Every proposed tool call becomes an Event, runs detectors + fusion + ladder
and returns a Decision. Taint labels flow from event characteristics and the
scripted-plan assumption (build prompt: in attack sessions ASSUME THE
INJECTION SUCCEEDED). Timing is measured with time.perf_counter.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from tether.contract import Contract
from tether.detectors import (
    BaselineTracker,
    contract_check,
    context_check,
    delegation_check,
    drift_check,
    intent_check,
    provenance_check,
)
from tether.events import Event
from tether.fusion import confidence, fusion_score
from tether.response import NarrowingCapsule, choose_action, narrow_from_contract
from tether.textgate import TextGate
from tether.types import Decision, DetectorResult


@dataclass
class SessionState:
    """Mutable per-session facts shared by detectors, fusion and the harness."""

    session: str
    executed_events: list[Event] = field(default_factory=list)
    executed_records: float = 0.0
    executed_bytes_out: float = 0.0
    untrusted_resources: set[str] = field(default_factory=set)
    restricted_resources: set[str] = field(default_factory=set)
    untrusted_event_ids: list[str] = field(default_factory=list)
    restricted_ids: list[str] = field(default_factory=list)
    egress_event_ids: list[str] = field(default_factory=list)
    restricted_read: bool = False
    untrusted_input: bool = False
    off_allowlist_egress: bool = False
    chain_completed: bool = False
    high_events: int = 0
    quarantined: bool = False
    isolated: bool = False
    narrowed: NarrowingCapsule | None = None
    change_status: str = "unexplained"
    alerts: list[Decision] = field(default_factory=list)
    baseline: BaselineTracker | None = None

    def snapshot(self) -> dict:
        return {
            "session": self.session,
            "quarantined": self.quarantined,
            "isolated": self.isolated,
            "restricted_read": self.restricted_read,
            "untrusted_input": self.untrusted_input,
            "off_allowlist_egress": self.off_allowlist_egress,
            "chain_completed": self.chain_completed,
        }


class Gateway:
    """One Gateway per run; one SessionState per session."""

    def __init__(
        self,
        contract: Contract,
        tracker: BaselineTracker,
        gate: TextGate | None = None,
        budget=None,
        change=None,
        phase2: bool = False,
    ) -> None:
        self.contract = contract
        self.tracker = tracker
        self.gate = gate
        self.budget = budget          # DriftBudget in Phase 2, None in Phase 1
        self.change = change
        self.phase2 = phase2
        self.states: dict[str, SessionState] = {}

    def state_for(self, session: str) -> SessionState:
        if session not in self.states:
            self.states[session] = SessionState(session=session, baseline=self.tracker)
        return self.states[session]

    # ------------------------------------------------------------------ main
    def evaluate(self, ev: Event) -> tuple[Decision, SessionState]:
        """Full path: enforcement -> labels -> detectors -> fusion -> ladder."""
        t0 = time.perf_counter()
        state = self.state_for(ev.session)

        # -- enforcement of an active narrowed capability set -----------------
        if state.isolated:
            return self._block(ev, t0, 100.0, "identity isolated; all calls blocked"), state
        if state.narrowed is not None and state.narrowed.denies_tool_class_ext(
            ev.tool, ev.data_class, ev.destination, self.contract, self.change
        ):
            return self._block(
                ev, t0, 70.0, state.narrowed.block_text(ev.tool, ev.data_class)
            ), state

        # -- taint labels on this event ---------------------------------------
        if self.contract.is_restricted_class(ev.data_class) and "RESTRICTED" not in ev.labels:
            ev.labels.append("RESTRICTED")
        if (ev.destination and not self.contract.egress_allowed(ev.destination, self.change)
                and "EXTERNAL_SEND" not in ev.labels):
            ev.labels.append("EXTERNAL_SEND")
        if self.contract.is_untrusted_class(ev.data_class) and "UNTRUSTED" not in ev.labels:
            ev.labels.append("UNTRUSTED")

        results: dict[str, DetectorResult] = {}
        results["contract"] = contract_check(ev, self.contract, state, self.change)
        results["provenance"] = provenance_check(ev, state)
        results["baseline"] = self.tracker.score_event(
            ev, state.executed_records, state.executed_bytes_out
        )
        results["intent"] = intent_check(ev, self.gate)
        if self.phase2:
            context_res = context_check(ev, self.contract, state)
            if context_res.score > 0.0:
                results["context"] = context_res
            if self.budget is not None:
                results["drift"] = drift_check(ev, self.budget)
            if len(ev.lineage) > 1:
                results["delegation"] = delegation_check(ev, self.contract, None)

        restricted_now = self.contract.is_restricted_class(ev.data_class)
        off_allowlist_now = bool(ev.destination) and not self.contract.egress_allowed(
            ev.destination, self.change
        )
        ev_change_status = self._change_status(ev, state)
        state.change_status = ev_change_status
        score = fusion_score(
            results,
            restricted_now,
            off_allowlist_now,
            state.restricted_read,
            state.off_allowlist_egress,
            ev_change_status,
        )
        conf = confidence(results, self.tracker.effective_maturity())

        corroborated = (
            state.chain_completed
            or (self.phase2 and results.get("context", DetectorResult("context", 0.0, 0.0)).score >= 1.0)
            or (state.high_events >= 1 and score >= 60)
        )
        action, rung = choose_action(score, corroborated)

        reasons: list[str] = []
        evidence: list[str] = []
        for name, res in results.items():
            for r in res.reasons:
                reasons.append(r)
            if res.evidence and res.score > 0.0:
                evidence.append(f"{name}:{res.evidence}")

        dec = Decision(
            event_id=ev.event_id,
            action=action,
            rung=rung,
            score=score,
            confidence=conf,
            reasons=reasons or ["behavior matches role"],
            evidence=evidence or ["within role baseline"],
            detector_scores={k: round(v.score, 3) for k, v in results.items()},
        )
        dec.latency_ms = self._ms(t0)

        if score >= 30:
            state.alerts.append(dec)
        if score >= 60:
            state.high_events += 1
        self._apply_rung(dec, ev, state)
        return dec, state

    # ------------------------------------------------------------- internals
    def _block(self, ev: Event, t0: float, score: float, reason: str) -> Decision:
        """Enforcement-path decision; score reflects the ladder floor in play
        (70 canonical restricted floor while narrowed, 100 under isolation)."""
        return Decision(
            event_id=ev.event_id,
            action="block",
            rung="enforcement",
            score=score,
            confidence=1.0,
            reasons=[reason],
            evidence=["active_enforcement"],
            latency_ms=self._ms(t0),
        )

    def _apply_rung(self, dec: Decision, ev: Event, state: SessionState) -> None:
        if dec.action == "allow":
            self.apply_effects(ev, state)
            return
        if dec.action == "narrow":
            state.narrowed = narrow_from_contract(self.contract, self.change)
        elif dec.action == "quarantine":
            # clean instance continues the task: discard context/taint, re-queue
            self._reset_taint(state)
            state.quarantined = True
        elif dec.action == "isolate":
            self._reset_taint(state)
            state.isolated = True

    def _reset_taint(self, state: SessionState) -> None:
        state.untrusted_resources.clear()
        state.restricted_resources.clear()
        state.untrusted_input = False
        state.restricted_read = False
        state.off_allowlist_egress = False
        state.chain_completed = False

    def apply_effects(self, ev: Event, state: SessionState) -> None:
        """World simulation: a committed call updates taint, quotas and flags."""
        state.executed_events.append(ev)
        state.executed_records += ev.records
        if ev.destination:
            state.executed_bytes_out += ev.bytes
        if "RESTRICTED" in ev.labels or self.contract.is_restricted_class(ev.data_class):
            state.restricted_read = True
            state.restricted_resources.add(ev.resource)
            state.restricted_ids.append(ev.event_id)
        if "UNTRUSTED" in ev.labels or self.contract.is_untrusted_class(ev.data_class):
            state.untrusted_input = True
            state.untrusted_resources.add(ev.resource)
            state.untrusted_event_ids.append(ev.event_id)
        if "EXTERNAL_SEND" in ev.labels:
            state.off_allowlist_egress = True
            state.egress_event_ids.append(ev.event_id)
        # Full chain bookkeeping: CARRY-tainted restricted data anywhere in the
        # session marks the chain as complete-with-exposure for corroboration.
        if "CARRY" in ev.labels and (state.restricted_read or state.untrusted_input):
            if state.untrusted_input and "RESTRICTED" in ev.labels:
                state.chain_completed = True
            if "EXTERNAL_SEND" in ev.labels:
                state.chain_completed = True

    def _change_status(self, ev: Event, state: SessionState) -> str:
        approved_tools = set(self.change.added_tools) if self.change else set()
        if ev.tool in approved_tools:
            return "explained"
        if state.untrusted_input:
            return "exposure_correlated"
        return "unexplained"

    @staticmethod
    def _ms(t0: float) -> float:
        return (time.perf_counter() - t0) * 1000.0
