"""In-process sliding-window rate limiter (per client IP).

This limiter is intentionally in-process and dependency-free.  It is
suitable for single-replica deployments and for the test harness.  For
multi-replica production use, replace it with a Redis-backed limiter.

Thread / async safety
---------------------
* ``threading.RLock`` protects the in-memory buckets.  FastAPI route
  handlers in this project are synchronous (``def``, not ``async def``)
  and run in Starlette's thread-pool, so a threading lock is sufficient
  and does not block the event loop.
* For ``async def`` dependencies that call into this module from the
  event loop, the critical section is short (microseconds) so the
  blocking impact is negligible.  If the project migrates to fully async
  handlers, replace the lock with ``asyncio.Lock`` or a lock-free
  structure.

Memory safety
-------------
* Empty / fully-expired buckets are evicted eagerly.
* A periodic sweep removes keys whose newest timestamp is older than the
  window — prevents unbounded growth from scanner / attacker IP rotation.
* A hard cap (``_MAX_KEYS``) triggers an LRU-style purge if the table
  grows unexpectedly.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

from fastapi import HTTPException, Request

_MAX_KEYS: int = 20_000
_SWEEP_INTERVAL_S: float = 120.0  # how often the periodic sweep may run
_PURGE_BATCH: int = 1_000  # max keys to evict in one sweep


class SlidingWindowLimiter:
    """Thread-safe sliding-window counter."""

    def __init__(self) -> None:
        self._events: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.RLock()
        self._last_sweep: float = time.monotonic()

    # -- internal helpers -------------------------------------------------

    def _evict_expired_bucket(self, bucket: list[float], now: float, window_s: float) -> list[float]:
        """Return bucket with entries older than *window_s* removed."""
        cutoff = now - window_s
        # Buckets are appended in monotonic order, so we can find the first
        # non-expired entry with a linear scan.  Typical bucket size is <100.
        # For larger buckets a bisect would be faster — not needed here.
        first_valid = 0
        for ts in bucket:
            if ts > cutoff:
                break
            first_valid += 1
        if first_valid:
            return bucket[first_valid:]
        return bucket

    def _maybe_sweep(self, now: float, window_s: float) -> None:
        """Periodically purge keys whose data is fully expired."""
        if now - self._last_sweep < _SWEEP_INTERVAL_S:
            return
        self._last_sweep = now
        # If table is small, skip the sweep entirely.
        if len(self._events) < _PURGE_BATCH:
            return
        expired_keys: list[str] = []
        for key, bucket in self._events.items():
            if not bucket:
                expired_keys.append(key)
                continue
            newest = bucket[-1]
            if now - newest >= window_s:
                # Every entry in the bucket is expired
                if all(now - ts >= window_s for ts in bucket):
                    expired_keys.append(key)
            if len(expired_keys) >= _PURGE_BATCH:
                break
        for key in expired_keys:
            self._events.pop(key, None)
        # Hard cap — if still over limit, evict oldest keys
        if len(self._events) > _MAX_KEYS:
            # defaultdict preserves insertion order (Python 3.7+); evict oldest
            to_remove = len(self._events) - _MAX_KEYS + _PURGE_BATCH
            for key in list(self._events.keys())[:to_remove]:
                self._events.pop(key, None)

    # -- public API -------------------------------------------------------

    def check(self, key: str, limit: int, window_s: float = 60.0) -> bool:
        """Return ``True`` if the request for *key* is within *limit*.

        The call is atomic: if the request is allowed the current timestamp
        is appended to the bucket.

        Args:
            key: Bucket identifier (typically client IP + route).
            limit: Maximum requests allowed within the window.
            window_s: Window size in seconds (default 60).
        """
        if limit <= 0:
            return False
        if not key:
            key = "unknown"
        now = time.monotonic()
        with self._lock:
            raw = self._events.get(key, [])
            bucket = self._evict_expired_bucket(raw, now, window_s)

            if len(bucket) >= limit:
                # Persist the pruned bucket (or evict if empty)
                if bucket:
                    self._events[key] = bucket
                elif key in self._events:
                    del self._events[key]
                self._maybe_sweep(now, window_s)
                return False

            bucket.append(now)
            self._events[key] = bucket
            self._maybe_sweep(now, window_s)
            return True

    def reset(self, key: str | None = None) -> None:
        """Reset *key* or the entire table (useful in tests)."""
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._events)


limiter: SlidingWindowLimiter = SlidingWindowLimiter()


def _client_ip(request: Request) -> str:
    """Best-effort client IP extraction.

    Prefers ``X-Forwarded-For`` only when the direct client is a trusted
    loopback (common in dev / single-proxy setups).  Otherwise uses the
    direct TCP peer to avoid header spoofing.
    """
    # Direct peer — always trustworthy
    direct = request.client.host if request.client else "unknown"
    # Only trust XFF if direct peer is loopback / private (i.e. a local proxy)
    xff = request.headers.get("x-forwarded-for", "").strip()
    if xff and direct in ("127.0.0.1", "::1", "localhost"):
        # Take the leftmost (original client) entry
        first = xff.split(",")[0].strip()
        if first:
            return first
    return direct


def enforce_rate_limit(request: Request, limit: int) -> None:
    """Enforce *limit* requests per 60 s for the request's client IP.

    Raises:
        HTTPException: 429 when the limit is exceeded.
    """
    # Use a composite key so different routes don't share the same bucket
    # when the caller wants per-route limiting.  For global limiting the
    # caller can pass a fixed key via a separate helper.
    ip = _client_ip(request)
    key = f"{ip}:{request.url.path}"
    # Fall back to IP-only key for auth endpoints where path varies little
    # — keep the original IP-only behaviour for backwards compat by also
    # checking the IP key for strict limits (auth).  For now we use the
    # composite key; behaviour is equivalent when limit is checked per-route.
    # To preserve the original contract (per-IP, not per-route) we use IP only
    # if the path is under /api/auth — callers pass the limit already scoped.
    if request.url.path.startswith("/api/auth"):
        key = ip
    if not limiter.check(key, limit):
        raise HTTPException(
            status_code=429,
            detail={"error": "rate_limited", "retry_after_s": 60},
            headers={"Retry-After": "60"},
        )
