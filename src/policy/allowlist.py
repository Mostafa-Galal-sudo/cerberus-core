from __future__ import annotations

ACTOR_ALLOWLIST: dict[str, frozenset[str]] = {
    "defense": frozenset({"isolate_device", "release_device", "open_incident", "log_alert"}),
    "response": frozenset({"isolate_device", "release_device"}),
    "operator": frozenset({"isolate_device", "release_device", "open_incident", "log_alert"}),
    "attack": frozenset({"attack_flood", "attack_bloat", "attack_rogue", "attack_spoof"}),
}

ALL_ALLOWED_ACTIONS: frozenset[str] = frozenset().union(*ACTOR_ALLOWLIST.values())


def is_allowed(actor: str, action: str) -> tuple[bool, str]:
    """Check whether `actor` is permitted to invoke `action`."""
    if not actor or actor not in ACTOR_ALLOWLIST:
        return False, f"unknown or unauthorized actor {actor!r}"
    if action not in ALL_ALLOWED_ACTIONS:
        return False, f"action {action!r} is not in the global allowlist"
    if action not in ACTOR_ALLOWLIST[actor]:
        return False, f"actor {actor!r} is not allowed to perform {action!r}"
    return True, "allowlist ok"
