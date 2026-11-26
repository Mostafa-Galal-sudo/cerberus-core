from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.simulator.devices import PROFILES

DEFAULT_LAB_DEVICES: frozenset[str] = frozenset(p.device_id for p in PROFILES)
_FORBIDDEN_TARGETS = frozenset({"*", "all", "broadcast", "any", ""})


@dataclass
class ScopePolicy:
    """Target and topic scope rules for lab-bounded execution."""

    allowed_devices: frozenset[str] = field(default_factory=lambda: DEFAULT_LAB_DEVICES)
    allowed_topic_prefixes: tuple[str, ...] = ("lab/",)
    allow_rogue_isolation: bool = True

    def check_target(self, actor: str, action: str, target: str) -> tuple[bool, str]:
        cleaned = (target or "").strip()
        if cleaned.lower() in _FORBIDDEN_TARGETS:
            return False, f"target {target!r} is forbidden (empty or wildcard)"

        if cleaned in self.allowed_devices:
            return True, "device in lab allowlist"

        # Defense/response/operator may isolate or open incidents on detected rogue devices
        if (
            self.allow_rogue_isolation
            and actor in {"defense", "response", "operator"}
            and action in {"isolate_device", "release_device", "open_incident", "log_alert"}
            and cleaned.startswith(("rogue_", "esp32_rogue_"))
        ):
            return True, "rogue device within defense scope"

        # Attack agent may spawn a simulated rogue device only with rogue prefix
        if actor == "attack" and action == "attack_rogue" and cleaned.startswith(("rogue_", "esp32_rogue_")):
            return True, "simulated rogue target within attack scope"

        return False, f"target {target!r} is outside allowed lab scope"

    def check_topic(self, topic: str | None) -> tuple[bool, str]:
        if topic is None:
            return True, "no topic specified"
        cleaned = topic.strip()
        if not cleaned or any(wild in cleaned for wild in ("#", "+")) or cleaned.startswith("$SYS"):
            return False, f"topic {topic!r} contains forbidden wildcard or system prefix"
        if not any(cleaned.startswith(prefix) for prefix in self.allowed_topic_prefixes):
            return False, f"topic {topic!r} is outside allowed prefixes {self.allowed_topic_prefixes}"
        return True, "topic in lab scope"

    def check_scope(
        self,
        actor: str,
        action: str,
        target: str,
        context: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        ok, reason = self.check_target(actor, action, target)
        if not ok:
            return False, reason
        if context and "topic" in context:
            return self.check_topic(context["topic"])
        return True, reason
