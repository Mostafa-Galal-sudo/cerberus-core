"""C3-T03 — Incident schema + timeline model.
detection -> evidence entries -> decision -> action -> outcome
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    DETECTION = "detection"
    EVIDENCE = "evidence"
    DECISION = "decision"
    ACTION = "action"
    OUTCOME = "outcome"


class Detection(BaseModel):
    """What the IDS hands to the pipeline (adapter point for src/detection)."""
    device_id: str
    score: float
    ts: float
    attack_type_hint: str | None = None
    source: str = "hybrid_ids"
    features: dict[str, float] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    ts: float = Field(default_factory=time.time)
    type: EventType
    actor: str
    summary: str
    payload: dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: "INC-" + uuid.uuid4().hex[:8])
    device_id: str
    severity: str = "medium"          # low | medium | high | critical
    status: str = "open"              # open | investigating | contained | closed | not_contained
    created_at: float = Field(default_factory=time.time)
    timeline: list[TimelineEvent] = Field(default_factory=list)

    def add_event(self, type: EventType, actor: str, summary: str,
                  payload: dict | None = None, ts: float | None = None) -> TimelineEvent:
        ev = TimelineEvent(type=type, actor=actor, summary=summary, payload=payload or {},
                           **({"ts": ts} if ts is not None else {}))
        self.timeline.append(ev)
        return ev

    def render(self) -> str:
        t0 = self.timeline[0].ts if self.timeline else 0
        lines = [f"{self.id}  device={self.device_id}  severity={self.severity}  status={self.status}"]
        for e in self.timeline:
            lines.append(f"  +{e.ts - t0:6.2f}s  [{e.type.value:<9}] {e.actor:<16} {e.summary}")
        return "\n".join(lines)


def severity_from_score(score: float) -> str:
    return "critical" if score >= 20 else "high" if score >= 8 else "medium" if score >= 3 else "low"
