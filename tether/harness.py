"""Session executor: runs one scripted plan through one defense mode.

- none: no defense, everything executes (the measurement baseline).
- textgate: only the stand-in text gate (comparison defense).
- tether: the full gateway path (detectors -> fusion -> ladder).

Leak accounting: a planned action flagged `leak` that executes adds its
records/bytes to the session's leak count. Utility = legitimate steps that
executed as planned.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tether.contract import Contract
from tether.detectors import BaselineTracker, DriftBudget
from tether.events import Event
from tether.gateway import Gateway
from tether.ledger import Ledger
from tether.textgate import COSINE_THRESHOLD, TextGate
from tether.types import ApprovedChange, Context, Decision


@dataclass
class PlannedAction:
    tool: str
    action: str
    resource: str
    data_class: str
    destination: str = ""
    bytes: int = 0
    records: int = 0
    carries: list[str] = field(default_factory=list)
    statement: str = ""
    content: str = ""        # document text for content-ingestion steps (textgate screens this)
    poisoned: bool = False   # instruction came from untrusted content (assume injection succeeded)
    injects: bool = False    # this step delivers the untrusted instruction (injection vector)
    legitimate: bool = True  # false for attacker-chosen steps
    leak: bool = False       # attacker-benefit transfer when executed


@dataclass
class SessionPlan:
    session: str
    attack: str
    tier: str = ""
    lineage: list[str] = field(default_factory=list)
    host: str = "agent-run01.internal"
    network: str = "corp"
    user_agent: str = "tether-agent/0.1"
    change: ApprovedChange | None = None
    steps: list[PlannedAction] = field(default_factory=list)


@dataclass
class RunConfig:
    contract: Contract
    tracker: BaselineTracker
    gate: TextGate | None
    budget: DriftBudget | None
    change: ApprovedChange | None
    phase2: bool


@dataclass
class SessionResult:
    session: str
    attack: str
    tier: str
    mode: str
    detected: bool = False
    first_alert_step: int | None = None
    caught_all_leaks: bool = True
    leak_records: int = 0
    leak_bytes: int = 0
    legit_total: int = 0
    legit_executed: int = 0
    skipped_injected: int = 0
    skipped_isolated_legit: int = 0
    max_score: float = 0.0
    latencies: list[float] = field(default_factory=list)
    steps: list[tuple[int, str, str, float]] = field(default_factory=list)  # step, tool, action, score
    decision_events: list[tuple[Event, Decision]] = field(default_factory=list)


def _event_for(plan: SessionPlan, idx: int, step: PlannedAction, contract: Contract) -> Event:
    labels: list[str] = []
    if step.poisoned:
        labels.append("CARRY")
    return Event(
        event_id=f"{plan.session}-{idx:03d}",
        step=idx,
        session=plan.session,
        agent=(plan.lineage or [contract.role])[-1],
        role=contract.role,
        blueprint_version=contract.blueprint_version,
        lineage=list(plan.lineage or [contract.role]),
        tool=step.tool,
        action=step.action,
        resource=step.resource,
        data_class=step.data_class,
        destination=step.destination,
        bytes=step.bytes,
        records=step.records,
        context=Context(host=plan.host, network=plan.network, user_agent=plan.user_agent),
        labels=labels,
        carries=list(step.carries),
        statement=step.statement,
    )


def _no_defense_dec(ev: Event) -> Decision:
    return Decision(event_id=ev.event_id, action="allow", rung="log", score=0.0, confidence=1.0)


def run_session(
    plan: SessionPlan, mode: str, config: RunConfig, ledger: Ledger
) -> SessionResult:
    """Execute one session plan in one mode; returns measured SessionResult."""
    result = SessionResult(session=plan.session, attack=plan.attack, tier=plan.tier, mode=mode)
    gateway: Gateway | None = None
    if mode == "tether":
        gateway = Gateway(
            contract=config.contract,
            tracker=config.tracker,
            gate=config.gate,
            budget=config.budget,
            change=plan.change or config.change,
            phase2=config.phase2,
        )
    elif mode == "textgate" and config.gate is None:
        raise ValueError("textgate mode requires a fitted TextGate")

    events_of_session: list[Event] = []
    # Injection-landing rule: poisoned steps only run when the instruction
    # actually reached the agent. Plans with no injection vector (A2's poisoned
    # tool description) count as pre-poisoned from the start.
    injection_landed = not any(s.injects for s in plan.steps)
    for idx, step in enumerate(plan.steps, start=1):
        act = f"{step.tool}@{step.resource}"
        result.steps.append((idx, step.tool, "planned", 0.0))
        if step.legitimate:
            result.legit_total += 1

        ev = _event_for(plan, idx, step, config.contract)

        if mode == "none":
            executed = True
            if step.injects:
                injection_landed = True
            result.legit_executed += 1 if step.legitimate else 0
            result.max_score = max(result.max_score, 0.0)

        elif mode == "textgate":
            if step.tool == "pdf.read" and step.content:
                # The stand-in gate screens document text at the ingestion
                # step only; it has no other visibility (comparison defense).
                cosine = config.gate.cosine(step.content)  # type: ignore[union-attr]
                executed = cosine >= COSINE_THRESHOLD
                score = 0.0 if executed else round(1.0 - cosine, 3)
                if not executed:
                    result.detected = True
                    if result.first_alert_step is None:
                        result.first_alert_step = idx
                result.max_score = max(result.max_score, score)
            elif step.poisoned:
                executed = injection_landed
                score = 0.0
            else:
                executed = True
                score = 0.0
            if executed and step.injects:
                injection_landed = True
            if executed:
                result.legit_executed += 1 if step.legitimate else 0

        else:  # tether
            state = gateway.state_for(plan.session)  # type: ignore[union-attr]
            if state.isolated:
                if step.legitimate:
                    result.skipped_isolated_legit += 1
                continue
            if (state.quarantined or not injection_landed) and step.poisoned:
                result.skipped_injected += 1
                continue
            dec, state = gateway.evaluate(ev)  # type: ignore[union-attr]
            ledger.append_event(ev)
            ledger.append_decision(dec)
            events_of_session.append(ev)
            result.decision_events.append((ev, dec))
            result.latencies.append(dec.latency_ms)
            result.steps[-1] = (idx, step.tool, dec.action, dec.score)
            executed = dec.action == "allow"
            if executed and step.injects:
                injection_landed = True
            result.max_score = max(result.max_score, dec.score)
            if not executed:
                result.detected = True
                if result.first_alert_step is None:
                    result.first_alert_step = idx
            if executed and step.legitimate:
                result.legit_executed += 1  # quotas/taint live in gateway.apply_effects

        # -- world effects + leak accounting ---------------------------------
        if executed:
            if mode != "tether":
                events_of_session.append(ev)
            if step.leak:
                result.leak_records += step.records
                result.leak_bytes += step.bytes
                result.caught_all_leaks = False

    if mode == "tether":
        gateway.end_session(plan.session)
        carry_any = any("CARRY" in ev.labels for ev in events_of_session)
        config.tracker.learn_session(
            events_of_session, alerts_any=bool(gateway.state_for(plan.session).alerts),  # type: ignore[union-attr]
            carry_any=carry_any,
        )
    return result
