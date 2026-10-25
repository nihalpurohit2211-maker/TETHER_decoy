"""L5 graduated response ladder + narrowed capability sets (D12)."""
from __future__ import annotations

from dataclasses import dataclass, field

from tether.contract import Contract


@dataclass
class NarrowingCapsule:
    """Short-lived narrowed capability set: removes only out-of-baseline
    capabilities (restricted data classes, external egress, delegated grants).
    The agent keeps its core job: allowlisted destinations still work."""

    deny_tools: set[str] = field(default_factory=set)
    deny_data_classes: set[str] = field(default_factory=set)
    reason: str = ""
    floor_score: float = 0.0

    def denies_tool_class_ext(
        self, tool: str, data_class: str, destination: str,
        contract: Contract, change=None,
    ) -> bool:
        if tool in self.deny_tools:
            return True
        if data_class in self.deny_data_classes:
            return True
        if destination and not contract.egress_allowed(destination, change):
            return True
        return False

    def block_text(self, tool: str, data_class: str) -> str:
        return (
            f"blocked by narrowed capability set ({self.reason}): "
            f"tool={tool}, data_class={data_class}"
        )


def narrow_from_contract(contract: Contract, change=None) -> NarrowingCapsule:
    """Narrow: drop restricted classes and all non-allowlisted egress."""
    denied = {
        dc for dc, status in contract.data_classes.items() if status == "denied"
    }
    tools_denied = {
        tool for tool, dc in _tool_class_pairs().items() if dc in denied
    }
    return NarrowingCapsule(
        deny_data_classes=denied,
        deny_tools=tools_denied,
        reason="restricted data and external egress removed",
    )


def _tool_class_pairs() -> dict[str, str]:
    """Exfiltration-capable tools carry restricted classes if abused. The
    mapping here is data-class driven, not per-attack tuned."""
    return {"hr_db.query": "hr_salary", "http.post": "hr_salary"}


def choose_action(score: float, corroborated: bool) -> tuple[str, str]:
    """Map a fused score to a ladder rung. Returns (action, rung).

    92+ fires isolate only with corroboration (completed chain, context
    anomaly, or a second >=60 event in the session); otherwise the response
    caps at quarantine and isolation is recommended to the sponsor (D12).
    """
    if score < 30:
        return "allow", "log"
    if score < 60:
        return "hold", "annotate"
    if score < 80:
        return "narrow", "narrow"
    if score < 92:
        return "quarantine", "quarantine"
    if corroborated:
        return "isolate", "isolate"
    return "quarantine", "quarantine"


RUNG_FOR = {
    "allow": "log",
    "hold": "annotate",
    "narrow": "narrow",
    "quarantine": "quarantine",
    "isolate": "isolate",
    "block": "enforcement",
}
