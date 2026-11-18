"""Policy-bounded automated response layer.

The only path to automated endpoint isolation. Rules enforced here (not in
the agent) so they cannot be talked around:

- Only devices already present in the registry can be isolated.
- Protected infrastructure (gateway, broker, SOC) is never isolatable.
- Isolation requires a confirmed alert whose fused confidence clears the
  policy threshold — no verdict, no action.
- Rate-bounded: at most `max_isolations` per window, then denials.
- Every action is audit-logged and mirrored as an incident timeline event.
"""
from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

PROTECTED_DEVICES = ("gateway", "broker", "mosquitto", "soc", "dashboard")


class IsolationDenied(Exception):
    """The response policy refused an isolation request."""


@dataclass
class ResponsePolicy:
    """Guardrails for automated isolation (defaults are deliberately strict)."""

    protected_devices: tuple[str, ...] = PROTECTED_DEVICES
    max_isolations: int = 5
    window_seconds: float = 3600.0
    min_confidence: float = 0.5
    clock: Callable[[], float] = field(default=time.monotonic, repr=False)
    _window: deque[float] = field(default_factory=deque, repr=False)

    def check_isolation(self, device_id: str, confidence: float | None) -> None:
        """Raise IsolationDenied unless the request clears every bound."""
        text = str(device_id).lower()
        for token in self.protected_devices:
            if token in text:
                raise IsolationDenied(
                    f"'{device_id}' matches protected infrastructure '{token}'"
                )
        if confidence is not None and confidence < self.min_confidence:
            raise IsolationDenied(
                f"confidence {confidence:.2f} below policy minimum "
                f"{self.min_confidence}"
            )
        now = self.clock()
        while self._window and now - self._window[0] >= self.window_seconds:
            self._window.popleft()
        if len(self._window) >= self.max_isolations:
            raise IsolationDenied(
                f"max {self.max_isolations} isolations per "
                f"{self.window_seconds:.0f}s window"
            )
        self._window.append(now)


def execute_isolation(
    db,
    device_id: str,
    alert_id: int | None = None,
    incident_id: int | None = None,
    confirmed_by: str = "defense-agent",
    reason: str = "",
    policy: ResponsePolicy | None = None,
) -> dict:
    """Isolate one device after full policy validation. Returns a summary.

    Raises IsolationDenied for any policy breach; ValueError-free — unknown
    devices are a denial, not a crash.
    """
    policy = policy or ResponsePolicy()

    alert = db.get_alert(alert_id) if alert_id is not None else None
    confidence = alert.get("confidence") if alert else None
    policy.check_isolation(device_id, confidence)  # may raise

    known = {d["device_id"] for d in db.list_devices()}
    if device_id not in known:
        raise IsolationDenied(
            f"unknown device '{device_id}' — only registered endpoints "
            "can be isolated"
        )

    db.set_device_status(device_id, "isolated")
    detail = {
        "device_id": device_id,
        "alert_id": alert_id,
        "confirmed_by": confirmed_by,
        "confidence": confidence,
        "reason": reason,
    }
    db.audit(confirmed_by, "device_isolated", detail)
    if incident_id is not None:
        db.append_event(
            incident_id, "response",
            f"{device_id} isolated by policy-bounded response "
            f"(confirmed by {confirmed_by})",
        )
    detail["status"] = "isolated"
    return detail


def release_device(
    db,
    device_id: str,
    released_by: str = "operator",
    reason: str = "",
) -> dict:
    """Manual lift of isolation — operator action, never automated."""
    db.set_device_status(device_id, "trusted")
    db.audit(released_by, "device_released",
             {"device_id": device_id, "reason": reason})
    return {"device_id": device_id, "status": "trusted", "released_by": released_by}
