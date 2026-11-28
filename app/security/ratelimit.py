"""Simple in-memory sliding-window rate limiter.

Good enough for a single-process local deployment. (Limitation: counters reset on
restart and are not shared between processes — documented in docs/limitations.md.)
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    """Thread-safe sliding-window rate limiter keyed by client or action identifier."""

    def __init__(self, limit: int, window_seconds: float = 60.0):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, n: int = 1) -> bool:
        """Record n hits for key if they fit in the window; otherwise record nothing and refuse."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10_000:  # prune idle keys so unauthenticated traffic can't grow memory
                for k in [k for k, q in self._hits.items() if not q or now - q[-1] > self.window]:
                    del self._hits[k]
            q = self._hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) + n > self.limit:
                return False
            q.extend([now] * n)
            return True

    def reset(self) -> None:
        """Clear all recorded hit timestamps (intended for test isolation)."""
        with self._lock:
            self._hits.clear()
