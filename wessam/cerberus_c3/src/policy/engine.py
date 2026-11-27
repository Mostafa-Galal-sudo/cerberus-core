"""C3-T01 — Policy layer.

Model proposes; policy disposes. The ONLY way to obtain an `ApprovedDecision`
is `PolicyEngine.evaluate()`. Executors (attacks / response) accept nothing but
an ApprovedDecision and redeem it with `PolicyEngine.consume()`, which checks
that the token was really issued by this engine and is single-use. So there is
no execution path that skips the policy.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_ALLOWLIST = Path(__file__).with_name("allowlist.yaml")
_MINT = object()  # private sentinel: only this module can mint tokens


@dataclass(frozen=True)
class ActionRequest:
    actor: str                      # "defense_agent" | "attack_agent" | ...
    action: str
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    incident_id: str | None = None


class ApprovedDecision:
    """Unforgeable-by-accident capability token. Do not construct directly."""
    __slots__ = ("decision_id", "request")

    def __init__(self, mint: object, decision_id: str, request: ActionRequest):
        if mint is not _MINT:
            raise PermissionError("ApprovedDecision can only be issued by PolicyEngine")
        self.decision_id = decision_id
        self.request = request


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    request: ActionRequest
    decision_id: str
    ts: float
    token: ApprovedDecision | None = None

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id, "allowed": self.allowed,
            "reason": self.reason, "ts": self.ts, "request": asdict(self.request),
        }


class PolicyEngine:
    def __init__(self, allowlist_path: str | Path = DEFAULT_ALLOWLIST,
                 audit_path: str | Path = "results/audit/policy_audit.jsonl",
                 clock=time.monotonic):
        self.cfg = yaml.safe_load(Path(allowlist_path).read_text())
        self.audit_path = Path(audit_path)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._lock = threading.Lock()
        self._recent: dict[str, deque] = defaultdict(deque)
        self._issued: dict[str, ApprovedDecision] = {}

    # ------------------------------------------------------------------ API
    def evaluate(self, req: ActionRequest) -> Decision:
        with self._lock:
            reason = self._check(req)
            allowed = reason is None
            decision_id = "DEC-" + uuid.uuid4().hex[:10]
            token = None
            if allowed:
                self._recent[req.actor].append(self._clock())
                token = ApprovedDecision(_MINT, decision_id, req)
                self._issued[decision_id] = token
            decision = Decision(allowed, reason or "allowed by policy", req,
                                decision_id, time.time(), token)
            self._audit({"event": "decision", **decision.to_dict()})
            return decision

    def consume(self, token: object, expected_actor: str | None = None) -> ActionRequest:
        """Redeem a token (single use). Executors call this before doing anything."""
        with self._lock:
            if not isinstance(token, ApprovedDecision):
                raise PermissionError("execution requires an ApprovedDecision from the policy layer")
            if self._issued.get(token.decision_id) is not token:
                raise PermissionError("unknown, forged or already-used decision")
            if expected_actor and token.request.actor != expected_actor:
                raise PermissionError(f"decision belongs to {token.request.actor}, not {expected_actor}")
            del self._issued[token.decision_id]
            self._audit({"event": "executed", "decision_id": token.decision_id,
                         "ts": time.time(), "request": asdict(token.request)})
            return token.request

    def describe_actions(self, actor: str) -> list[dict]:
        """Catalog of what `actor` may do (used to build LLM prompts)."""
        a = self.cfg["actors"][actor]
        out = []
        for name in a["allowed_actions"]:
            spec = self.cfg["actions"][name]
            out.append({"action": name, "target_kind": spec["target_kind"],
                        "min_confidence": spec["min_confidence"], "params": spec.get("params", {})})
        return out

    @property
    def scope(self) -> dict:
        return self.cfg["scope"]

    # ------------------------------------------------------------- internals
    def _check(self, req: ActionRequest) -> str | None:
        actors = self.cfg["actors"]
        if req.actor not in actors:
            return f"unknown actor '{req.actor}'"
        if req.action not in actors[req.actor]["allowed_actions"]:
            return f"action '{req.action}' is not in the allowlist for {req.actor}"
        spec = self.cfg["actions"].get(req.action)
        if spec is None:
            return f"action '{req.action}' has no policy definition"
        err = self._check_target(spec["target_kind"], req.target)
        if err:
            return err
        err = self._check_params(spec.get("params", {}), req.params)
        if err:
            return err
        if not isinstance(req.confidence, (int, float)) or not 0 <= req.confidence <= 1:
            return "confidence must be a number in [0, 1]"
        if req.confidence < spec["min_confidence"]:
            return (f"confidence {req.confidence:.2f} below minimum "
                    f"{spec['min_confidence']:.2f} for '{req.action}'")
        rl = actors[req.actor]["rate_limit"]
        q, now = self._recent[req.actor], self._clock()
        while q and now - q[0] > rl["per_seconds"]:
            q.popleft()
        if len(q) >= rl["max_actions"]:
            return f"rate limit exceeded for {req.actor} ({rl['max_actions']}/{rl['per_seconds']}s)"
        return None

    def _check_target(self, kind: str, target: str) -> str | None:
        sc = self.cfg["scope"]
        devices, infra = sc["devices"], sc["infrastructure"]
        if not isinstance(target, str):
            return "target must be a string"
        ok = {
            "device": target in devices,
            "device_or_infra": target in devices or target in infra,
            "any": target in devices or target in infra,
            "topic": target.startswith(sc["topic_prefix"]) and len(target) <= 128,
        }.get(kind, False)
        return None if ok else f"target '{target}' is out of scope for this action ({kind})"

    def _check_params(self, spec: dict, params: dict) -> str | None:
        if not isinstance(params, dict):
            return "params must be an object"
        unknown = set(params) - set(spec)
        if unknown:
            return f"unexpected params: {sorted(unknown)}"
        for name, rule in spec.items():
            if name not in params:
                return f"missing required param '{name}'"
            v, t = params[name], rule["type"]
            if t == "int":
                if isinstance(v, bool) or not isinstance(v, int):
                    return f"param '{name}' must be an integer"
                if not rule["min"] <= v <= rule["max"]:
                    return f"param '{name}'={v} outside [{rule['min']}, {rule['max']}]"
            elif t == "device":
                if v not in self.cfg["scope"]["devices"]:
                    return f"param '{name}'={v!r} is not a device in scope"
            elif t == "str":
                if not isinstance(v, str) or len(v) > rule.get("max_len", 128):
                    return f"param '{name}' invalid"
        return None

    def _audit(self, record: dict) -> None:
        with self.audit_path.open("a") as f:
            f.write(json.dumps(record, default=str) + "\n")
