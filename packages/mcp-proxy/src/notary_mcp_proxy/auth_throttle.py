"""Failed-token throttling for the HTTP endpoint, per source address.

Rule: `max_failures` wrong tokens from one address inside `window_seconds` lock that address out
for `lockout_seconds`. While locked out EVERY request from the address is refused with 429 and a
`Retry-After`, even one carrying the correct token (an attacker must not learn that a guess was
right, and a lockout that a valid token could skip would be no lockout). A success resets the
address's counter. Requests refused during the lockout do not extend it.

Tradeoff: an attacker who shares the address with the user (another process on the machine, or
every client behind one reverse proxy) can lock the user out for the lockout. That is a denial of
service of a local tool, chosen over letting the token be guessed; loopback is the default bind.

The table is bounded (`max_entries`): when full, expired entries go first, then the oldest entry.
The clock is injected (monotonic seconds) so tests never sleep. Nothing here sees a token.
"""

import math
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

DEFAULT_MAX_FAILURES = 5
DEFAULT_LOCKOUT_SECONDS = 60.0
MAX_FAILURES_LIMIT = 1000
MAX_LOCKOUT_SECONDS = 86400.0
DEFAULT_MAX_ENTRIES = 4096


def validate_throttle(max_failures: int, lockout_seconds: float) -> None:
    """Raise `ValueError` for a setting that would disable or distort the throttle."""
    if not 1 <= max_failures <= MAX_FAILURES_LIMIT:
        raise ValueError(f"max failures must be from 1 to {MAX_FAILURES_LIMIT}")
    if not (math.isfinite(lockout_seconds) and 0 < lockout_seconds <= MAX_LOCKOUT_SECONDS):
        raise ValueError(f"lockout seconds must be above 0 and at most {MAX_LOCKOUT_SECONDS:g}")


@dataclass
class _Record:
    failures: int
    window_ends: float
    locked_until: float


class AuthThrottle:
    def __init__(
        self,
        clock: Callable[[], float],
        *,
        max_failures: int = DEFAULT_MAX_FAILURES,
        lockout_seconds: float = DEFAULT_LOCKOUT_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        validate_throttle(max_failures, lockout_seconds)
        if max_entries < 1:
            raise ValueError("max entries must be at least 1")
        self._clock = clock
        self._max_failures = max_failures
        self._lockout = lockout_seconds
        self._window = lockout_seconds
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._records: OrderedDict[str, _Record] = OrderedDict()

    def retry_after(self, address: str) -> int:
        """Whole seconds (at least 1) until `address` may try again, or 0 when it is not locked."""
        now = self._clock()
        with self._lock:
            record = self._records.get(address)
            if record is None or record.locked_until <= now:
                return 0
            return max(1, math.ceil(record.locked_until - now))

    def failed(self, address: str) -> None:
        now = self._clock()
        with self._lock:
            record = self._records.get(address)
            if record is not None and record.locked_until > now:
                return  # already locked out: a refused request does not extend it
            if record is None or record.window_ends <= now or record.locked_until > 0:
                record = _Record(0, now + self._window, 0.0)
                self._records[address] = record
            self._records.move_to_end(address)
            record.failures += 1
            if record.failures >= self._max_failures:
                record.locked_until = now + self._lockout
            self._evict(now)

    def succeeded(self, address: str) -> None:
        with self._lock:
            self._records.pop(address, None)

    def size(self) -> int:
        with self._lock:
            return len(self._records)

    def _evict(self, now: float) -> None:
        if len(self._records) <= self._max_entries:
            return
        for key in [
            key
            for key, record in self._records.items()
            if record.locked_until <= now and record.window_ends <= now
        ]:
            del self._records[key]
        while len(self._records) > self._max_entries:
            self._records.popitem(last=False)
