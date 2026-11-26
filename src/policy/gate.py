from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.storage.db import utc_now

from .allowlist import is_allowed
from .audit import AuditLogger
from .ratelimit import RateLimiter
from .scope import ScopePolicy


class PolicyDeniedError(PermissionError):
    """Raised when PolicyGate denies a privileged action."""


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    actor: str
    action: str
    target: str
    reason: str
    ts_utc: str


class PolicyGate:
    """Single authorization gate: allowlist -> scope -> rate limit -> audit log."""

    def __init__(
        self,
        *,
        conn: sqlite3.Connection | None = None,
        log_path: str | Path | None = None,
        scope: ScopePolicy | None = None,
        ratelimiter: RateLimiter | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.scope = scope or ScopePolicy()
        self.ratelimiter = ratelimiter or RateLimiter()
        self.audit = audit or AuditLogger(conn=conn, log_path=log_path)

    def authorize(
        self,
        actor: str,
        action: str,
        target: str,
        context: dict[str, Any] | None = None,
        *,
        now: float | None = None,
    ) -> PolicyDecision:
        ts = utc_now()
        ok, reason = is_allowed(actor, action)
        if ok:
            ok, reason = self.scope.check_scope(actor, action, target, context)
        if ok:
            ok, reason = self.ratelimiter.check_and_record(actor, action, now=now)

        verdict = "ALLOW" if ok else "DENY"
        self.audit.record(
            actor=actor,
            action=action,
            target=target,
            verdict=verdict,
            reason=reason,
            context=context,
            ts_utc=ts,
        )
        return PolicyDecision(
            allowed=ok,
            actor=actor,
            action=action,
            target=target,
            reason=reason,
            ts_utc=ts,
        )

    def require(
        self,
        actor: str,
        action: str,
        target: str,
        context: dict[str, Any] | None = None,
        *,
        now: float | None = None,
    ) -> PolicyDecision:
        decision = self.authorize(actor, action, target, context, now=now)
        if not decision.allowed:
            raise PolicyDeniedError(
                f"policy denied {actor}/{action} on {target!r}: {decision.reason}"
            )
        return decision
