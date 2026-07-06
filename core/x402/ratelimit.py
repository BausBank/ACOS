"""In-memory token-bucket rate limiter for the Trust Toll cashier (Stage 17).

The "rate-limit" leg of the wider Stage-17 build. A free, unauthenticated 402
endpoint invites abuse (each verification is real compute), so we throttle by
key (client IP and/or payer address) with a classic token bucket: a key may
burst up to ``capacity`` requests, then is limited to ``rate`` per second as the
bucket refills.

Single-process / asyncio: the refill+consume step has no ``await`` inside, so
the event loop never interleaves it - no locking needed. ``clock`` is injectable
so tests are deterministic without sleeping.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable


@dataclass
class _Bucket:
    tokens: float
    last: float


class TokenBucket:
    """Per-key token bucket. ``allow(key)`` returns True if a token was spent."""

    def __init__(
        self,
        rate_per_sec: float,
        capacity: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if rate_per_sec <= 0 or capacity <= 0:
            raise ValueError("rate_per_sec and capacity must be positive")
        self.rate = float(rate_per_sec)
        self.capacity = float(capacity)
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = self._clock()
        b = self._buckets.get(key)
        if b is None:
            b = _Bucket(tokens=self.capacity, last=now)
            self._buckets[key] = b
        elapsed = now - b.last
        if elapsed > 0:
            b.tokens = min(self.capacity, b.tokens + elapsed * self.rate)
            b.last = now
        if b.tokens >= cost:
            b.tokens -= cost
            return True
        return False

    def tokens_left(self, key: str) -> float:
        b = self._buckets.get(key)
        return b.tokens if b is not None else self.capacity
