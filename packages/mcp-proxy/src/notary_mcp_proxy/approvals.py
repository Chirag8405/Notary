"""The approval desk: where an escalated call waits for the user's answer.

The worker thread (the one that owns the Gateway) opens an entry for an escalated call and waits on
it. Decisions arrive from other threads (the control socket) and only RECORD a choice here; the
worker alone turns the choice into `Gateway.approve` / `Gateway.reject`, so the Gateway is never
touched from a second thread.

Fail closed: a timeout, a cancel by the agent and the end of the agent's input all give "reject",
and a decision that arrives after the deadline or after the wait ended is refused. Nothing here
can approve on its own.

The clock is injected (`time.monotonic` by default) and the wait is a condition variable polled in
short slices, so tests advance a fake clock instead of sleeping.
"""

import base64
import hmac
import secrets
import threading
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field

from notary_core.models import NotaryModel

Choice = Literal["approve", "reject"]
CodeResult = Literal["ok", "unknown", "code"]
"""`decide_with_code`: recorded, no such open card, or the code was missing or wrong."""
Cause = Literal["user", "timeout", "cancelled", "closed"]
"""Why a wait ended: the user answered, the deadline passed, the agent cancelled the call, or the
agent's input ended."""

POLL_SECONDS = 0.1
"""How often a waiting call looks at the clock, the cancel flag and the end of input."""
PATIENCE = 30.0
"""Only a failing test waits this long (`wait_for_open`)."""
CODE_BYTES = 5
"""Entropy of an approval code (40 bits, shown as 8 base32 characters)."""
MAX_BAD_CODES = 3
"""Wrong codes a card takes before it is rejected: a guess cannot be repeated until it fits."""


class Pending(NotaryModel):
    """One card waiting for the user. `card_text` is built from labels only and made printable."""

    endorsement_id: str
    call_id: str
    tool: str
    card_text: str
    remaining_approvals: Annotated[int, Field(ge=0)]


@dataclass(frozen=True, slots=True)
class Answer:
    choice: Choice
    cause: Cause


@dataclass(slots=True)
class _Entry:
    pending: Pending
    deadline: float
    choice: Choice | None = None
    closed: bool = False
    code: str | None = None
    bad_codes: int = 0


def printable(text: str) -> str:
    """The text with control characters made visible, so a card cannot drive a terminal.

    Card rows quote values an attacker may have written (an email body, a file): an escape
    sequence in one must not reach the user's terminal as a command. Newlines stay.
    """
    out: list[str] = []
    for char in text:
        if char == "\n" or unicodedata.category(char) not in {"Cc", "Cf", "Cs", "Co", "Cn"}:
            out.append(char)
        else:
            out.append(f"\\u{ord(char):04x}" if ord(char) <= 0xFFFF else f"\\U{ord(char):08x}")
    return "".join(out)


def _code_matches(expected: str | None, given: str | None) -> bool:
    """True when no code is required, or the given one equals it (case and spaces ignored)."""
    if expected is None:
        return True
    return given is not None and hmac.compare_digest(given.strip().upper(), expected)


def _random_code() -> str:
    return base64.b32encode(secrets.token_bytes(CODE_BYTES)).decode("ascii")


class ApprovalDesk:
    def __init__(
        self,
        *,
        timeout_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        poll_seconds: float = POLL_SECONDS,
        require_code: bool = False,
        new_code: Callable[[], str] | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("the approval timeout must be positive")
        self._timeout = timeout_seconds
        self._clock = clock
        self._poll = poll_seconds
        self._require_code = require_code
        self._new_code = new_code or _random_code
        self._cond = threading.Condition()
        self._entries: dict[str, _Entry] = {}
        self._opened = 0

    @property
    def timeout_seconds(self) -> float:
        return self._timeout

    def open(self, pending: Pending) -> str | None:
        """Start waiting for the user on this card; the deadline starts now.

        Returns the one-time approval code the control socket will ask for, or None when codes
        are off. The code is never part of `pending()` or the card: the caller shows it only on
        the user's own channel.
        """
        with self._cond:
            if pending.endorsement_id in self._entries:
                raise ValueError("endorsement already open")
            code = self._new_code() if self._require_code else None
            self._entries[pending.endorsement_id] = _Entry(
                pending=pending, deadline=self._clock() + self._timeout, code=code
            )
            self._opened += 1
            self._cond.notify_all()
            return code

    def wait(self, endorsement_id: str, cancelled: Callable[[], bool]) -> Choice:
        """The user's choice; "reject" on timeout or cancel. The entry is closed on return."""
        return self.resolve(endorsement_id, cancelled=cancelled).choice

    def resolve(
        self,
        endorsement_id: str,
        *,
        cancelled: Callable[[], bool],
        closed: Callable[[], bool] = lambda: False,
    ) -> Answer:
        """Block until the card is answered, the deadline passes, or the call is cancelled.

        `cancelled` (the agent's `notifications/cancelled`) and `closed` (the agent's input ended)
        win over a recorded choice: a call nobody can receive must not run. The entry is closed
        before this returns, so a late `decide` is refused.
        """
        with self._cond:
            entry = self._entries.get(endorsement_id)
            if entry is None:
                return Answer("reject", "closed")
            try:
                while True:
                    if closed():
                        return Answer("reject", "closed")
                    if cancelled():
                        return Answer("reject", "cancelled")
                    if entry.choice is not None:
                        return Answer(entry.choice, "user")
                    if self._clock() >= entry.deadline:
                        return Answer("reject", "timeout")
                    self._cond.wait(self._poll)
            finally:
                entry.closed = True
                del self._entries[endorsement_id]

    def decide(self, endorsement_id: str, choice: Choice) -> bool:
        """Record the user's choice (any thread); False when unknown, decided, closed or expired."""
        with self._cond:
            entry = self._entries.get(endorsement_id)
            if entry is None or entry.closed or entry.choice is not None:
                return False
            if self._clock() >= entry.deadline:
                return False  # a late approval never counts
            entry.choice = choice
            self._cond.notify_all()
            return True

    def decide_with_code(self, endorsement_id: str, choice: Choice, code: str | None) -> CodeResult:
        """The control socket's `decide`: an approval must carry the card's one-time code.

        A reject needs no code (it is always safe). A wrong or missing code approves nothing and
        counts; the card is rejected at the `MAX_BAD_CODES`-th, so the code cannot be guessed.
        """
        with self._cond:
            entry = self._entries.get(endorsement_id)
            if entry is None or entry.closed or entry.choice is not None:
                return "unknown"
            if choice == "approve" and not _code_matches(entry.code, code):
                entry.bad_codes += 1
                if entry.bad_codes >= MAX_BAD_CODES and self._clock() < entry.deadline:
                    entry.choice = "reject"
                    self._cond.notify_all()
                return "code"
            return "ok" if self.decide(endorsement_id, choice) else "unknown"

    def pending(self) -> tuple[Pending, ...]:
        """The cards still open for a decision, oldest first."""
        with self._cond:
            now = self._clock()
            return tuple(
                entry.pending
                for entry in self._entries.values()
                if entry.choice is None and not entry.closed and now < entry.deadline
            )

    def wake(self) -> None:
        """Make waiting calls look at the clock and the cancel flags now."""
        with self._cond:
            self._cond.notify_all()

    def wait_for_open(self, count: int, timeout: float = PATIENCE) -> bool:
        """Block until `count` cards have been opened in all (tests use this, never a sleep)."""
        with self._cond:
            return self._cond.wait_for(lambda: self._opened >= count, timeout)
