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

import threading
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field

from notary_core.models import NotaryModel

Choice = Literal["approve", "reject"]
Cause = Literal["user", "timeout", "cancelled", "closed"]
"""Why a wait ended: the user answered, the deadline passed, the agent cancelled the call, or the
agent's input ended."""

POLL_SECONDS = 0.1
"""How often a waiting call looks at the clock, the cancel flag and the end of input."""
PATIENCE = 30.0
"""Only a failing test waits this long (`wait_for_open`)."""


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


class ApprovalDesk:
    def __init__(
        self,
        *,
        timeout_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        poll_seconds: float = POLL_SECONDS,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("the approval timeout must be positive")
        self._timeout = timeout_seconds
        self._clock = clock
        self._poll = poll_seconds
        self._cond = threading.Condition()
        self._entries: dict[str, _Entry] = {}
        self._opened = 0

    @property
    def timeout_seconds(self) -> float:
        return self._timeout

    def open(self, pending: Pending) -> None:
        """Start waiting for the user on this card; the deadline starts now."""
        with self._cond:
            if pending.endorsement_id in self._entries:
                raise ValueError("endorsement already open")
            self._entries[pending.endorsement_id] = _Entry(
                pending=pending, deadline=self._clock() + self._timeout
            )
            self._opened += 1
            self._cond.notify_all()

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
