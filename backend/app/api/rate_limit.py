"""Minimal in-process sliding-window rate limiter (per client IP)."""
import threading
import time
from collections import defaultdict

from fastapi import HTTPException, Request


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._events: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_s: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = [t for t in self._events[key] if now - t < window_s]
            if len(bucket) >= limit:
                self._events[key] = bucket
                return False
            bucket.append(now)
            self._events[key] = bucket
            return True


limiter = SlidingWindowLimiter()


def enforce_rate_limit(request: Request, limit: int) -> None:
    client = request.client.host if request.client else "unknown"
    if not limiter.check(client, limit):
        raise HTTPException(status_code=429, detail={"error": "rate_limited", "retry_after_s": 60})
