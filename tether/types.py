"""Shared value types for the Tether simulation (stdlib only)."""
from __future__ import annotations

import dataclasses
from typing import Optional


@dataclasses.dataclass
class Context:
    """Execution context of one tool call; stolen-token signals live here."""

    host: str = ""
    network: str = ""
    user_agent: str = ""


@dataclasses.dataclass
class DetectorResult:
    """One detector's verdict: probability in [0,1] plus an evidence pointer.

    weight is the detector's effective weight in the fusion (already scaled,
    e.g. by baseline maturity). reasons use fixed template strings only.
    """

    name: str
    score: float
    weight: float
    evidence: str = ""
    reasons: list[str] = dataclasses.field(default_factory=list)
    extra: dict = dataclasses.field(default_factory=dict)

    @property
    def active(self) -> bool:
        return self.score > 0.0


@dataclasses.dataclass
class Decision:
    """Gateway output for one proposed tool call."""

    event_id: str
    action: str           # allow | hold | narrow | quarantine | isolate | block
    rung: str             # log | annotate | narrow | quarantine | isolate | enforcement
    score: float          # 0..100
    confidence: float     # 0..1
    reasons: list[str] = dataclasses.field(default_factory=list)
    evidence: list[str] = dataclasses.field(default_factory=list)
    detector_scores: dict = dataclasses.field(default_factory=dict)
    latency_ms: float = 0.0
    counterfactual: str = ""


@dataclasses.dataclass
class ApprovedChange:
    """An approved change record raised through the legitimacy channel."""

    change_id: str
    description: str
    added_tools: list[str] = dataclasses.field(default_factory=list)
    added_destinations: list[str] = dataclasses.field(default_factory=list)
    added_data_classes: dict = dataclasses.field(default_factory=dict)
    status: str = "approved"
