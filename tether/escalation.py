"""Identity-scoped escalation for the response ladder (M10, D47).

Why this exists
---------------
v1's ladder was top-heavy. `choose_action` needs >= 92 for `isolate`, but the
highest canonical floor is 90, and the 80-91 `quarantine` band is usually
pre-empted by the narrowed capability set installed at 70: the next dangerous
call is blocked by the capsule before fusion ever sees a quarantining score.
So in practice only allow/hold/narrow/block fired.

The dishonest fix is to lower the isolate band to 90. The honest fix is that a
*repeat* offender should escalate: the same identity that already triggered
containment and came back is a different risk than a first-time offender, and
that difference is history, not a bigger score.

Policy (declared before measurement, PREREG H4)
-----------------------------------------------
severity: block=1, narrow=1, quarantine=2, isolate=3, hold/allow=0.
level 0: no offense in the window            -> v1 bands unchanged
level 1: 1 <= severity < 3                   -> narrow becomes quarantine
level 2: severity >= 3                       -> narrow/quarantine become isolate

The window decays: a session with no offense clears the history after
`window` sessions. Containment itself stays per-session (a session-scoped
isolate blocks the rest of that session); this class only decides which rung a
new offense lands on. Deliberately NOT a role-wide credential revocation -
that would take out legitimate work, which the PS's fifth demand forbids.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY = {
    "allow": 0,
    "hold": 0,        # annotate: not containment, does not escalate
    "block": 1,       # enforcement by the narrowed capability set
    "narrow": 1,
    "quarantine": 2,
    "isolate": 3,
}

REPEAT_WINDOW = 25   # sessions without an offense that clear the history


@dataclass
class EscalationState:
    """Offense history per identity (role+blueprint), shared across sessions."""

    window: int = REPEAT_WINDOW
    tick: int = 0
    severity: float = 0.0
    last_offense_tick: int = -(10 ** 9)
    blocked_this_tick: bool = False
    history: list[tuple[int, str, str]] = field(default_factory=list)  # (tick, rung, session)

    def begin_session(self) -> None:
        """Advance the clock and decay stale history (a quiet agent is not a
        permanent suspect)."""
        self.tick += 1
        self.blocked_this_tick = False
        if self.tick - self.last_offense_tick >= self.window:
            self.severity = 0.0

    @property
    def level(self) -> int:
        if self.severity >= 3:
            return 2
        if self.severity >= 1:
            return 1
        return 0

    def record(self, action: str, session: str) -> None:
        sev = SEVERITY.get(action, 0)
        if sev <= 0:
            return
        if action == "block":
            # One session's blocked probes are one offense, not one per probe:
            # otherwise a capsule that denies three calls in a row counts as
            # three escalations and jumps straight to isolation.
            if self.blocked_this_tick:
                return
            self.blocked_this_tick = True
        self.severity += sev
        self.last_offense_tick = self.tick
        self.history.append((self.tick, action, session))

    def next_action(self, base_action: str, session: str = "") -> tuple[str, bool]:
        """Apply escalation to a band-mapped action. Returns (action, escalated)."""
        level = self.level
        action = base_action
        if level >= 2 and base_action in ("narrow", "quarantine"):
            action = "isolate"
        elif level >= 1 and base_action == "narrow":
            action = "quarantine"
        return action, action != base_action
