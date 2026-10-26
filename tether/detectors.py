"""L2 detectors. Each returns a DetectorResult: score in [0,1] + evidence.

Determinism note: scores are fixed rules, not fitted numbers. Baseline uses
pseudo-counts seeded from the contract (cold start, D13) and robust z-scores
(D14). The drift budget is a Phase-2 detector and stays silent until enabled.
"""
from __future__ import annotations

from collections import Counter

from tether.contract import Contract
from tether.events import Event
from tether.textgate import TextGate
from tether.types import DetectorResult

W_CONTRACT = 0.9
W_PROVENANCE = 0.9
W_DELEGATION = 0.7
W_BASELINE = 0.5
W_CONTEXT = 0.7
W_DRIFT = 0.5
W_INTENT = 0.2

PSEUDO_COUNT = 10.0          # cold-start pseudo counts per implied behavior
MATURITY_FLOOR = 0.2         # effective maturity floor in fusion (D13)
Z_TRIGGER = 4.0              # robust-z level that starts penalizing volume
Z_CAP_DIV = 8.0              # z score is capped at min(1, z/Z_CAP_DIV)
FIRST_SEEN_TOOL = 0.6
FIRST_SEEN_DEST = 0.5
FIRST_SEEN_HOST = 0.7


# ---------------------------------------------------------------- contract
def contract_check(
    ev: Event, contract: Contract, state, change=None
) -> DetectorResult:
    """Deterministic check: tools, data class, egress, per-session ceilings."""
    name = "contract"
    reasons: list[str] = []
    parts: list[str] = []
    score = 0.0

    if not contract.is_tool_permitted(ev.tool, change):
        score = 1.0
        reasons.append(f"tool {ev.tool} is not in the permitted set for role {contract.role}")
        parts.append("clause=permitted_tools")
    if contract.is_restricted_class(ev.data_class):
        score = 1.0
        reasons.append(
            f"data class {ev.data_class} is denied for role {contract.role}"
        )
        parts.append("clause=data_classes")
    elif contract.class_status(ev.data_class) == "unknown":
        score = max(score, 0.7)
        reasons.append(f"data class {ev.data_class} is not declared in the contract")
        parts.append("clause=data_classes")
    if ev.destination and not contract.egress_allowed(ev.destination, change):
        score = 1.0
        reasons.append(f"destination {ev.destination} is not on the egress allowlist")
        parts.append("clause=egress_allowlist")
    if ev.records and state.executed_records + ev.records > contract.records_per_session:
        score = 1.0
        reasons.append(
            f"proposed read would exceed the session record ceiling "
            f"({state.executed_records + ev.records} > {contract.records_per_session})"
        )
        parts.append("clause=ceilings")
    if ev.bytes and ev.destination and state.executed_bytes_out + ev.bytes > contract.bytes_out_per_session:
        score = 1.0
        reasons.append(
            f"proposed send would exceed the session egress byte ceiling "
            f"({state.executed_bytes_out + ev.bytes} > {contract.bytes_out_per_session})"
        )
        parts.append("clause=ceilings")

    evidence = ",".join(parts) or "within contract"
    return DetectorResult(name=name, score=score, weight=W_CONTRACT, evidence=evidence, reasons=reasons)


# -------------------------------------------------------------- provenance
def provenance_check(ev: Event, state) -> DetectorResult:
    """Rule of Two: untrusted -> restricted -> external send in one session,
    or attacker-tainted (CARRY) data moving out."""
    name = "provenance"
    out = DetectorResult(name=name, score=0.0, weight=W_PROVENANCE, evidence="no chain progress")
    reasons: list[str] = []
    is_external = "EXTERNAL_SEND" in ev.labels

    carry_tainted = any(
        rid in state.untrusted_resources or rid in state.restricted_resources
        for rid in ev.carries
    )
    if is_external and carry_tainted:
        out.score = 1.0
        reasons.append("tainted payload moved toward an external destination")
        out.evidence = f"carries={list(ev.carries)} dest={ev.destination}"
    elif carry_tainted and ev.destination:
        out.score = 0.5
        reasons.append("tainted payload referenced by an outbound transfer")
        out.evidence = f"carries={list(ev.carries)} dest={ev.destination}"
    elif is_external and state.restricted_read:
        out.score = 1.0
        reasons.append("restricted data read earlier in this session is being sent out")
        out.evidence = f"restricted_ids={state.restricted_ids} dest={ev.destination}"
    if is_external and state.untrusted_input and out.score < 0.5:
        out.score = max(out.score, 0.5)
        reasons.append("send follows untrusted input in the same session")
        out.evidence = f"untrusted={state.untrusted_event_ids} dest={ev.destination}"
    out.reasons = reasons
    return out


# ---------------------------------------------------------------- baseline
class BaselineTracker:
    """Role-level statistical baseline keyed by (role, blueprint_version).

    Learns only from alert-free sessions with no untrusted-to-action taint
    (D13). Contract-implied behavior is pre-seeded as pseudo-counts so a
    brand-new agent is guarded on day one without being flagged for doing
    its own job (build-prompt test: 'a brand-new instance is guarded on its
    first action', and zero false alarms on paper-legitimate behavior).
    """

    def __init__(self, contract: Contract, change=None) -> None:
        self.contract = contract
        self.pairs: Counter = Counter()
        self.dests: Counter = Counter()
        self.hosts: Counter = Counter()
        self.records_hist: list[float] = []
        self.bytes_hist: list[float] = []
        self.learned_sessions = 0
        for pair in contract.implied_table(change):
            self.pairs[pair] += PSEUDO_COUNT / 2
        for tool in contract.permitted_tools:
            self.pairs[(tool, "")] += PSEUDO_COUNT / 2
        for tool in contract.permitted_tools:
            self.pairs[(tool, "")] += PSEUDO_COUNT / 2
        for dest in contract.egress_allowlist:
            self.dests[dest] += PSEUDO_COUNT / 2
        for ctx in contract.execution_contexts:
            self.hosts[ctx.get("host", "agent-run01.internal")] += PSEUDO_COUNT

    # -- learning -----------------------------------------------------------
    def learn_session(self, events: list[Event], alerts_any: bool, carry_any: bool) -> None:
        if alerts_any or carry_any:
            return
        self.learned_sessions += 1
        session_records = 0.0
        session_bytes = 0.0
        for ev in events:
            self.pairs[(ev.tool, ev.data_class)] += 1
            self.pairs[(ev.tool, "")] += 1
            if ev.destination:
                self.dests[ev.destination] += 1
            self.hosts[ev.context.host] += 1
            session_records += ev.records
            session_bytes += ev.bytes
        self.records_hist.append(session_records)
        self.bytes_hist.append(session_bytes)

    # -- scoring ------------------------------------------------------------
    @property
    def maturity(self) -> float:
        k = self.learned_sessions
        return k / (k + PSEUDO_COUNT)

    def effective_maturity(self) -> float:
        return max(self.maturity, MATURITY_FLOOR)

    def _robust_z(self, values: list[float], x: float) -> float:
        if len(values) < 8:
            return 0.0
        s = sorted(values)
        n = len(s)
        med = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0

        def absdev(v: float) -> float:
            return abs(v - med)

        devs = sorted(absdev(v) for v in values)
        mad = devs[n // 2] if n % 2 else (devs[n // 2 - 1] + devs[n // 2]) / 2.0
        if mad <= 1e-9:
            mad = med * 0.25 or 1.0
        return max(0.0, (x - med) / (1.4826 * mad))

    def score_event(
        self, ev: Event, session_records: float, session_bytes: float
    ) -> DetectorResult:
        name = "baseline"
        reasons: list[str] = []
        parts: list[str] = []
        score = 0.0
        w = W_BASELINE * self.effective_maturity()

        if self.pairs[(ev.tool, ev.data_class)] < 0.5 and self.pairs[(ev.tool, "")] < 0.5:
            score = max(score, FIRST_SEEN_TOOL)
            reasons.append(f"tool/pair {ev.tool}/{ev.data_class} is first-seen for this role")
            parts.append(f"first_seen=(tool={ev.tool})")
        if ev.destination and self.dests[ev.destination] < 0.5 and self.pairs[(ev.tool, "")] > 0:
            score = max(score, FIRST_SEEN_DEST)
            reasons.append(f"destination {ev.destination} is first-seen for this role")
            parts.append(f"first_seen=(dest={ev.destination})")
        z_rec = self._robust_z(self.records_hist, session_records + ev.records)
        if z_rec > Z_TRIGGER:
            score = max(score, min(1.0, z_rec / Z_CAP_DIV))
            reasons.append(f"session record volume above role baseline (robust z={z_rec:.1f})")
            parts.append("volume_type=records")
        z_bytes = self._robust_z(self.bytes_hist, session_bytes + ev.bytes)
        if z_bytes > Z_TRIGGER:
            score = max(score, min(1.0, z_bytes / Z_CAP_DIV))
            reasons.append(f"session egress volume above role baseline (robust z={z_bytes:.1f})")
            parts.append("volume_type=bytes")
        if ev.context.host and self.hosts[ev.context.host] < 0.5:
            score = max(score, FIRST_SEEN_HOST)
            reasons.append(f"execution host {ev.context.host} is first-seen for this role")
            parts.append(f"first_seen=(host={ev.context.host})")

        evidence = ",".join(parts) or "matches role baseline"
        return DetectorResult(name=name, score=score, weight=w, evidence=evidence, reasons=reasons)


# ------------------------------------------------------------------ intent
def intent_check(ev: Event, gate: TextGate | None) -> DetectorResult:
    """Advisory only, lowest weight; never the gate."""
    name = "intent"
    if gate is None or not ev.statement:
        return DetectorResult(name=name, score=0.0, weight=W_INTENT, evidence="no statement")
    s = gate.score_offpurpose(ev.statement)
    reasons = [f"statement overlaps declared purpose weakly (cosine {1.0 - s:.2f})"] if s > 0.5 else []
    return DetectorResult(
        name=name, score=s, weight=W_INTENT, evidence=f"cosine={1.0 - s:.2f}", reasons=reasons
    )


# ------------------------------------------------------------------ context
def context_check(ev: Event, contract: Contract, state) -> DetectorResult:
    """Phase 2: stolen-token replay detection from execution context."""
    name = "context"
    out = DetectorResult(name=name, score=0.0, weight=W_CONTEXT, evidence="context as expected")
    reasons: list[str] = []
    expected_hosts = {c["host"] for c in contract.execution_contexts}
    expected_nets = {c["network"] for c in contract.execution_contexts}
    expected_ua = {c["user_agent"] for c in contract.execution_contexts}
    hits = 0
    parts = []
    if ev.context.host and ev.context.host not in expected_hosts:
        hits += 1
        parts.append(f"host={ev.context.host}")
        reasons.append(f"call came from unregistered execution host {ev.context.host}")
    if ev.context.network and ev.context.network not in expected_nets:
        hits += 1
        parts.append(f"network={ev.context.network}")
        reasons.append(f"call came over unregistered network {ev.context.network}")
    if not hits:
        return out
    if ev.context.user_agent and ev.context.user_agent not in expected_ua:
        hits += 1
        parts.append(f"user_agent={ev.context.user_agent}")
        reasons.append("user agent does not match the registered fleet")
    hits = min(3, hits)
    if hits >= 2:
        out.score = 1.0
    elif hits == 1:
        out.score = 0.6
    out.evidence = ",".join(parts)
    out.reasons = reasons
    return out


# ------------------------------------------------------------------- drift
class DriftBudget:
    """Phase 2 drift budget: a one-sided standardized CUSUM of per-session
    outbound RECORD volume per destination against a FROZEN anchor pseudo-
    seeded from the contract's implied email pattern; refreshed only by an
    approved change (D23, D26). Per-session byte ceilings are already enforced
    deterministically by the contract check, so records are the exfiltration-
    relevant volume tracked here. k=0.5 and h=5 are textbook one-sided CUSUM
    values, chosen a priori. The score always reflects committed (completed
    session) evidence, so detection lags the first session by design.
    Silent in Phase 1 (gateway only receives a budget when
    phase2 is on)."""

    DEFAULT_ANCHOR = {"mu_records": 1.0, "sigma_records": 1.0}

    def __init__(
        self,
        anchor: dict[str, dict[str, float]],
        k: float = 0.5,
        h: float = 8.0,
        review_latency: int = 10,
        review_keep_z: float = 2.0,
    ) -> None:
        self.anchor = anchor            # frozen; may be replaced via refresh
        self.k = k
        self.h = h                      # calibrated on null traffic (D26)
        self.review_latency = review_latency   # modeled sponsor review delay
        self.review_keep_z = review_keep_z     # attempted-volume bar to keep
        self.cusum: dict[str, float] = {}
        self.pending: dict[str, int] = {}
        self.latched: set[str] = set()  # alarmed destinations stay contained
        self.review_counters: dict[str, int] = {}
        self.review_attempts: dict[str, int] = {}
        self.trajectory: list[list] = []  # [session, dest, records, cusum, latched]
        self.sessions_seen = 0

    def refresh(self, anchor: dict[str, dict[str, float]]) -> None:
        """Only an approved change may re-freeze the anchor; it also clears
        latched alarms (the human review is the reset path)."""
        self.anchor = dict(anchor)
        self.cusum.clear()
        self.pending.clear()
        self.latched.clear()
        self.review_counters.clear()
        self.review_attempts.clear()

    def accumulate(self, destination: str, records: int) -> None:
        """Record executed outbound volume for the open session."""
        if destination:
            self.pending[destination] = self.pending.get(destination, 0) + records

    def record_attempt(self, destination: str, records: int) -> None:
        """Record a PROPOSED outbound volume. While a destination's alarm is
        latched this is the review evidence: an attacker keeps pushing volume
        even though the sends are held; ordinary traffic does not."""
        if destination in self.latched:
            self.review_attempts[destination] = (
                self.review_attempts.get(destination, 0) + records
            )

    def end_session(self, session: str = "") -> None:
        """Commit the session's per-destination volume into the CUSUM, latch
        alarms at the decision interval and run the sponsor-review clock.
        Every anchor destination updates every session: zero volume is
        evidence too (otherwise untouched destinations could never decay)."""
        self.sessions_seen += 1
        for dest, a in self.anchor.items():
            mu = a.get("mu_records", self.DEFAULT_ANCHOR["mu_records"])
            sg = a.get("sigma_records", self.DEFAULT_ANCHOR["sigma_records"])
            records = self.pending.get(dest, 0)
            z = (records - mu) / max(sg, 1e-9)
            self.cusum[dest] = max(0.0, self.cusum.get(dest, 0.0) + z - self.k)
            if self.cusum[dest] >= self.h and dest not in self.latched:
                self.latched.add(dest)
                self.review_counters[dest] = 0
                self.review_attempts[dest] = 0
            self.trajectory.append([
                session or str(self.sessions_seen), dest, records,
                round(self.cusum[dest], 3), 1 if dest in self.latched else 0,
            ])
        self.pending.clear()
        for dest in list(self.latched):
            self.review_counters[dest] = self.review_counters.get(dest, 0) + 1
            if self.review_counters[dest] >= self.review_latency:
                a = self.anchor.get(dest, self.DEFAULT_ANCHOR)
                mu = a.get("mu_records", self.DEFAULT_ANCHOR["mu_records"])
                sg = a.get("sigma_records", self.DEFAULT_ANCHOR["sigma_records"])
                avg = self.review_attempts.get(dest, 0) / self.review_latency
                if (avg - mu) / max(sg, 1e-9) > self.review_keep_z:
                    # sustained attempted volume above anchor: keep contained
                    self.review_counters[dest] = 0
                    self.review_attempts[dest] = 0
                else:
                    # review found no sustained push: approve and reset
                    self.latched.discard(dest)
                    self.cusum[dest] = 0.0
                    self.review_counters.pop(dest, None)
                    self.review_attempts.pop(dest, None)

    def score(self, destination: str) -> float:
        """Drift score in [0,1]: 1.0 while the destination's alarm is latched,
        else 0. The alarm latches (subject to sponsor review) so an attacker
        cannot simply wait out the statistic and resume."""
        if not destination:
            return 0.0
        return 1.0 if destination in self.latched else 0.0


def drift_check(ev: Event, budget: DriftBudget) -> DetectorResult:
    """Score an outbound event against the committed cumulative drift budget."""
    name = "drift"
    if not ev.destination:
        return DetectorResult(name=name, score=0.0, weight=W_DRIFT, evidence="local call")
    s = budget.score(ev.destination)
    cus = budget.cusum.get(ev.destination, 0.0)
    reasons = [
        f"cumulative record drift budget exceeded for destination {ev.destination} "
        f"(cusum {cus:.1f} over sessions)"
    ] if s >= 1.0 else []
    return DetectorResult(
        name=name, score=s, weight=W_DRIFT,
        evidence=f"dest={ev.destination} cusum_records={cus:.1f}",
        reasons=reasons,
    )


# --------------------------------------------------------------- delegation
def delegation_check(
    ev: Event, contract: Contract, parent_grant_tools: list[str] | None
) -> DetectorResult:
    """Phase 2: authority intersection on delegated envelopes."""
    name = "delegation"
    out = DetectorResult(name=name, score=0.0, weight=W_DELEGATION, evidence="no delegation this event")
    reasons = []
    if len(ev.lineage) < 2 or ev.tool != "inter_agent.send":
        return out
    parent, child = ev.lineage[-2], ev.lineage[-1]
    if parent not in contract.delegatees and child not in contract.delegatees:
        # Unseen caller->callee edge unless the pair is registered.
        out.score = max(out.score, 0.5)
        reasons.append(f"caller-to-callee edge {parent}->{child} is not a registered delegatee link")
        out.evidence = f"edge={parent}->{child}"
    if parent_grant_tools is not None and "inter_agent.send" not in parent_grant_tools:
        out.score = 1.0
        reasons.append(f"agent {parent} has no granted authority to delegate to agent {child}")
        out.evidence = f"authority={parent_grant_tools}"
        return out
    if ev.carries and out.score < 1.0:
        # cross-agent taint inside the envelope payload
        carry_tainted = bool(ev.labels and "CARRY" in ev.labels)
        if carry_tainted:
            out.score = max(out.score, 0.8)
            reasons.append("inter-agent message carries tainted data")
            out.evidence = f"carries={ev.carries}"
    out.reasons = reasons
    return out
