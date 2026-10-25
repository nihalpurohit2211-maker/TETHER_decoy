"""L0 role contract: the only trusted, non-learnable fact in Tether."""
from __future__ import annotations

import json
import os
from typing import Any, Optional

from tether.types import ApprovedChange

DEFAULT_CONTRACT_PATH = os.path.join(os.path.dirname(__file__), "contract.json")

RESTRICTED_STATUSES = {"denied"}
UNTRUSTED_STATUSES = {"allowed_untrusted"}


class Contract:
    """Immutable role contract with the helpers detectors need."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self.role: str = spec["role"]
        self.blueprint_version: str = spec["blueprint_version"]
        self.sponsor: str = spec["sponsor"]
        self.purpose: str = spec["purpose"]
        self.permitted_tools: list[str] = list(spec["permitted_tools"])
        self.data_classes: dict[str, str] = dict(spec["data_classes"])
        self.egress_allowlist: list[str] = list(spec["egress_allowlist"])
        ceilings = spec.get("ceilings", {})
        self.records_per_session: int = int(ceilings.get("records_per_session", 200))
        self.bytes_out_per_session: int = int(ceilings.get("bytes_out_per_session", 50000))
        self.delegatees: list[str] = list(spec.get("delegatees", []))
        self.execution_contexts: list[dict[str, str]] = list(
            spec.get("execution_contexts", [])
        )

    # --- data classes -----------------------------------------------------
    def class_status(self, data_class: str) -> str:
        """'allowed' | 'allowed_untrusted' | 'denied' | 'unknown'."""
        return self.data_classes.get(data_class, "unknown")

    def is_restricted_class(self, data_class: str) -> bool:
        return self.class_status(data_class) in RESTRICTED_STATUSES

    def is_untrusted_class(self, data_class: str) -> bool:
        return self.class_status(data_class) in UNTRUSTED_STATUSES

    # --- tools / egress, optionally via an approved change -----------------
    def is_tool_permitted(
        self, tool: str, change: Optional[ApprovedChange] = None
    ) -> bool:
        if tool in self.permitted_tools:
            return True
        return bool(change and tool in change.added_tools)

    def egress_allowed(
        self, destination: str, change: Optional[ApprovedChange] = None
    ) -> bool:
        if not destination:
            return True  # local tools have no egress leg
        if destination in self.egress_allowlist:
            return True
        return bool(change and destination in change.added_destinations)

    def implied_table(self, change: Optional[ApprovedChange] = None) -> set[tuple[str, str]]:
        """(tool, data_class) pairs the contract implies; seeds baseline cold start."""
        pairs: set[tuple[str, str]] = set()
        class_map = {
            "pricing_api.read": ["supplier_pricing"],
            "pdf.read": ["supplier_docs"],
            "purchase_request.create": ["supplier_pricing"],
            "email.send": ["supplier_pricing", "supplier_docs"],
        }
        for tool, dcs in class_map.items():
            for dc in dcs:
                pairs.add((tool, dc))
        if change is not None:
            for tool in change.added_tools:
                pairs.add((tool, change.added_data_classes.get(tool, "supplier_pricing")))
        return pairs


def load_contract(path: str | None = None) -> Contract:
    with open(path or DEFAULT_CONTRACT_PATH, "r", encoding="utf-8") as fh:
        return Contract(json.load(fh))


APPROVED_CHANGE_101 = ApprovedChange(
    change_id="CHG-101",
    description=(
        "Add contract_clause_search tool (supplier data) for fastener RFQ work; "
        "human sponsor approved; egress list unchanged."
    ),
    added_tools=["contract_clause_search"],
    added_data_classes={"contract_clause_search": "supplier_pricing"},
    added_destinations=[],
    status="approved",
)
