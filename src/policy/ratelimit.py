from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
    "isolate_device": (5, 60.0),
    "release_device": (5, 60.0),
    "open_incident": (20, 60.0),
    "log_alert": (60, 60.0),
    "attack_flood": (3, 60.0),
    "attack_bloat": (3, 60.0),
    "attack_rogue": (3, 60.0),
    "attack_spoof": (3, 60.0),
}


class RateLimiter:
    """Thread-safe sliding-window rate limiter keyed by (actor, action)."""

    def __init__(
        self,
        limits: dict[str, tuple[int, float]] | None = None,
        default_limit: tuple[int, float] = (10, 60.0),
    ) -> None:
        self.limits = dict(DEFAULT_LIMITS if limits is None else limits)
        self.default_limit = default_limit
        self._buckets: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check_and_record(
        self,
        actor: str,
        action: str,
        now: float | None = None,
    ) -> tuple[bool, str]:
        ts = time.monotonic() if now is None else float(now)
        max_calls, window_sec = self.limits.get(action, self.default_limit)
        cutoff = ts - window_sec
        key = (actor, action)

        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= max_calls:
                return False, f"rate limit exceeded for {actor}/{action} ({max_calls} per {window_sec:.0f}s)"
            bucket.append(ts)
        return True, "rate limit ok"
