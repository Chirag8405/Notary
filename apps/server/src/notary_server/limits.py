"""Per-client rate limits for the playground routes (#242).

A sliding window per client key: at most `limit` hits in the last `window_seconds`. The clock is a
parameter (`time.monotonic` in production), so a test advances time instead of sleeping and this
module reads no clock itself. The table of clients is bounded: when it is full the client that was
used longest ago is dropped, so a flood of addresses cannot grow it without limit.
"""

import math
import threading
from collections import OrderedDict, deque
from collections.abc import Callable

Clock = Callable[[], float]
"""Seconds from a monotonic source."""

DEFAULT_MAX_KEYS = 4096


class RateLimiter:
    def __init__(
        self,
        *,
        limit: int,
        window_seconds: float,
        clock: Clock,
        max_keys: int = DEFAULT_MAX_KEYS,
    ) -> None:
        if limit < 1 or window_seconds <= 0 or max_keys < 1:
            raise ValueError("limit, window and max_keys must be positive")
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._max_keys = max_keys
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Record a hit for `key` and return True, or return False and record nothing."""
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                hits = deque[float]()
                self._hits[key] = hits
                self._evict()
            else:
                self._hits.move_to_end(key)
            self._forget_old(hits, now)
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            return True

    def retry_after(self, key: str) -> int:
        """Whole seconds (at least 1) until a hit for `key` would be allowed again."""
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                return 1
            self._forget_old(hits, now)
            if len(hits) < self._limit:
                return 1
            return max(1, math.ceil(hits[0] + self._window - now))

    def keys(self) -> int:
        """How many clients are tracked."""
        with self._lock:
            return len(self._hits)

    def _forget_old(self, hits: deque[float], now: float) -> None:
        while hits and now - hits[0] >= self._window:
            hits.popleft()

    def _evict(self) -> None:
        while len(self._hits) > self._max_keys:
            self._hits.popitem(last=False)


class PlaygroundLimits:
    """The three budgets of the playground: Hijacked Mode starts, Hijacked Mode calls, and the
    other POSTs that run a scenario (`poison`, `attacks/{id}/run`, `arena`). Each has its own
    window per client, so a busy arena does not use up a judge's calls."""

    def __init__(self, *, starts: RateLimiter, calls: RateLimiter, runs: RateLimiter) -> None:
        self.starts = starts
        self.calls = calls
        self.runs = runs


class RateLimitedError(Exception):
    """The client is over its budget; the response is 429 with `Retry-After`."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("too many requests")
        self.retry_after = retry_after
