"""L1 event: every proposed tool call becomes one of these."""
from __future__ import annotations

import dataclasses

from tether.types import Context


@dataclasses.dataclass
class Event:
    event_id: str
    step: int
    session: str
    agent: str
    role: str
    blueprint_version: str
    lineage: list[str]                 # delegation path, e.g. ["A", "B"]
    tool: str
    action: str                        # read | create | send | post
    resource: str                      # resource id or short payload handle
    data_class: str
    destination: str                   # egress target ("" for local tools)
    bytes: int
    records: int
    context: Context
    labels: list[str]                  # UNTRUSTED | RESTRICTED | EXTERNAL_SEND | CARRY | CROSS_AGENT
    carries: list[str]                 # resource ids referenced by an outbound payload
    statement: str                     # agent's rationale; advisory signal only

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)
