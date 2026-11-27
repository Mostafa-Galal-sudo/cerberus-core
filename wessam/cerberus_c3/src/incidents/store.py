from __future__ import annotations

from pathlib import Path

from .models import Detection, EventType, Incident, severity_from_score


class IncidentStore:
    """One JSON file per incident (easy for the dashboard to read)."""

    def __init__(self, root: str | Path = "results/incidents"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def create(self, detection: Detection) -> Incident:
        inc = Incident(device_id=detection.device_id, severity=severity_from_score(detection.score))
        inc.add_event(EventType.DETECTION, detection.source,
                      f"anomaly on {detection.device_id} (score={detection.score:.1f}, "
                      f"hint={detection.attack_type_hint})",
                      detection.model_dump(), ts=None)
        self.save(inc)
        return inc

    def save(self, inc: Incident) -> Path:
        path = self.root / f"{inc.id}.json"
        path.write_text(inc.model_dump_json(indent=2))
        return path

    def load(self, incident_id: str) -> Incident:
        return Incident.model_validate_json((self.root / f"{incident_id}.json").read_text())

    def list_ids(self) -> list[str]:
        return sorted(p.stem for p in self.root.glob("INC-*.json"))
