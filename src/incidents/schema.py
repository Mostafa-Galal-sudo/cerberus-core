from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

VALID_SEVERITIES = ("low", "medium", "high", "critical")
VALID_STATUSES = ("open", "investigating", "mitigated", "resolved", "dismissed")


@dataclass
class IncidentEvent:
    incident_id: str
    ts_utc: str
    kind: str
    actor: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentRecord:
    id: str
    created_utc: str
    updated_utc: str
    device_id: str
    severity: str
    status: str
    detection_ref: str
    reasoning_summary: str = ""
    decision: str = ""
    action: str = ""
    outcome: str = ""
    timeline: list[IncidentEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}; expected one of {VALID_SEVERITIES}")
        if self.status not in VALID_STATUSES:
            raise ValueError(f"invalid status {self.status!r}; expected one of {VALID_STATUSES}")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timeline"] = [ev.to_dict() for ev in self.timeline]
        return data
