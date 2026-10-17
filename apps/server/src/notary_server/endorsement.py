"""The Endorsement Service: the human-in-the-loop decider for ESCALATE.

The agent runner stops at an escalation and asks a decider. The decider published here registers
the pending diff card, blocks the runner's worker thread, and returns whatever the user's
`endorsement_decision` command said. It never approves anything by itself: the only path to
"approve" is an accepted `approve` command for exactly that run and endorsement, sent on the
socket that owns the card. A timeout, a cancelled run or a disconnect all reject (fail closed).
The ledger write itself is the engine's (`resolve_escalation`, authority `user_endorsed`); this
module only carries the decision.
"""

import threading
import time
from collections import OrderedDict
from typing import Literal

from notary_core.endorsement import render_card
from notary_core.models import Command, Endorsement, EndorsementDecisionCommand, NotaryModel
from notary_server.agent_runner import EscalationAnnouncer, EscalationDecider
from notary_server.commands import (
    CLOSE_COMMAND_CONFLICT,
    CLOSE_UNSUPPORTED_COMMAND,
    CommandContext,
    CommandHandler,
    CommandRejected,
)

SubmitResult = Literal["accepted", "unknown_endorsement", "already_resolved"]
DEFAULT_TIMEOUT_SECONDS: float = 300.0
MAX_RUNS: int = 256
"""Runs whose slots are kept for idempotency; the oldest run without a waiter is dropped."""

RunKey = tuple[str, str]
"""`(owner, run_id)`. Run ids repeat across sockets (`run-<scenario>-<lane>`), so the owner (a
server-side secret per socket, never sent to a client) is what tells two runs apart (#201)."""

Decision = Literal["approve", "reject", "use_nearest"]


class PendingEndorsement(NotaryModel):
    run_id: str
    endorsement: Endorsement
    card_text: str
    """`render_card(endorsement.card)`: built from labels only, never from agent prose."""
    remaining_approvals: int
    """`max_approvals` minus the approvals accepted so far for this run, when registered."""


class _Slot:
    def __init__(self, endorsement: Endorsement, remaining_approvals: int) -> None:
        self.endorsement = endorsement
        self.remaining_approvals = remaining_approvals
        self.decision: Decision | None = None


class _Run:
    def __init__(self) -> None:
        self.slots: dict[str, _Slot] = {}
        self.approved = 0
        self.cancelled = False

    def reject_unresolved(self) -> None:
        for slot in self.slots.values():
            if slot.decision is None:
                slot.decision = "reject"

    def has_waiter(self) -> bool:
        return any(slot.decision is None for slot in self.slots.values())


class EndorsementRun:
    """The two hooks of one run: `announce` registers a card, `decide` waits for its answer."""

    def __init__(self, announce: EscalationAnnouncer, decide: EscalationDecider) -> None:
        self.announce = announce
        self.decide = decide


class EndorsementBroker:
    def __init__(self, *, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout_seconds
        self._cond = threading.Condition()
        self._runs: OrderedDict[RunKey, _Run] = OrderedDict()

    def decider_for(self, run_id: str, *, owner: str, max_approvals: int) -> EscalationDecider:
        """The decider of one run (see `start_run`)."""
        return self.start_run(run_id, owner=owner, max_approvals=max_approvals).decide

    def start_run(self, run_id: str, *, owner: str, max_approvals: int) -> EndorsementRun:
        """Start a run owned by `owner`. State left by an earlier run of the same owner and id is
        rejected and dropped, so a stale decision can never answer a new run. A run of another
        owner with the same id is a different run and is left alone.

        `announce(endorsement)` registers the pending card without waiting; the runner calls it
        before it hands the `endorsement_requested` event to the client, so the card is already
        on `pending` and answerable when the client sees the event (#195). `decide(endorsement)`
        waits for the answer; it registers the card too when `announce` was not called."""
        key = (owner, run_id)
        with self._cond:
            previous = self._runs.pop(key, None)
            if previous is not None:
                previous.reject_unresolved()
                self._cond.notify_all()
            self._runs[key] = _Run()
            self._evict()

        def announce(endorsement: Endorsement) -> None:
            with self._cond:
                self._slot(key, endorsement, max_approvals)

        def decide(endorsement: Endorsement) -> Decision:
            return self._wait(key, endorsement, max_approvals)

        return EndorsementRun(announce, decide)

    def _evict(self) -> None:
        for old_key in list(self._runs):
            if len(self._runs) <= MAX_RUNS:
                return
            if not self._runs[old_key].has_waiter():
                del self._runs[old_key]

    def _slot(self, key: RunKey, endorsement: Endorsement, max_approvals: int) -> _Slot:
        """The slot of the card, created on first sight. Call with the lock held."""
        run = self._runs.setdefault(key, _Run())
        slot = run.slots.get(endorsement.endorsement_id)
        if slot is None:
            remaining = max(max_approvals - run.approved, 0)
            slot = _Slot(endorsement, remaining)
            run.slots[endorsement.endorsement_id] = slot
            if run.cancelled:
                slot.decision = "reject"
        return slot

    def _wait(self, key: RunKey, endorsement: Endorsement, max_approvals: int) -> Decision:
        with self._cond:
            slot = self._slot(key, endorsement, max_approvals)
            deadline = time.monotonic() + self._timeout
            while slot.decision is None:
                left = deadline - time.monotonic()
                if left <= 0:
                    slot.decision = "reject"
                    break
                self._cond.wait(left)
            return slot.decision

    def submit(self, command: EndorsementDecisionCommand, *, owner: str) -> SubmitResult:
        """Record the answer of `owner`. A card of another owner is "unknown_endorsement": the
        command cannot tell a missing card from somebody else's, so it learns nothing."""
        with self._cond:
            run = self._runs.get((owner, command.run_id))
            slot = None if run is None else run.slots.get(command.endorsement_id)
            if run is None or slot is None:
                return "unknown_endorsement"
            if slot.decision is not None:
                return "already_resolved"
            slot.decision = command.decision
            if command.decision == "approve":
                run.approved += 1
            self._cond.notify_all()
            return "accepted"

    def pending(self, run_id: str, *, owner: str) -> tuple[PendingEndorsement, ...]:
        """The unresolved cards of one owner's run."""
        with self._cond:
            run = self._runs.get((owner, run_id))
            return () if run is None else self._unresolved(run_id, run)

    def pending_for_run(self, run_id: str) -> tuple[PendingEndorsement, ...]:
        """The unresolved cards of every run with this id, whoever owns them. Unauthenticated:
        for tests and diagnostics, never for a route. A client learns the fate of its cards from the
        run's own events."""
        with self._cond:
            return tuple(
                entry
                for (_owner, key_run_id), run in self._runs.items()
                if key_run_id == run_id
                for entry in self._unresolved(run_id, run)
            )

    @staticmethod
    def _unresolved(run_id: str, run: _Run) -> tuple[PendingEndorsement, ...]:
        return tuple(
            PendingEndorsement(
                run_id=run_id,
                endorsement=slot.endorsement,
                card_text=render_card(slot.endorsement.card),
                remaining_approvals=slot.remaining_approvals,
            )
            for slot in run.slots.values()
            if slot.decision is None
        )

    def cancel_run(self, run_id: str, *, owner: str) -> None:
        """Reject every unresolved slot of the owner's run; a later escalation of it is rejected
        at once. A run of another owner with the same id is not touched."""
        with self._cond:
            run = self._runs.get((owner, run_id))
            if run is None:
                return
            run.cancelled = True
            run.reject_unresolved()
            self._cond.notify_all()

    def handler(self) -> CommandHandler:
        """For `CommandRouter.register("endorsement_decision", ...)`."""

        def handle(command: Command, context: CommandContext) -> None:
            if not isinstance(command, EndorsementDecisionCommand):
                raise CommandRejected(
                    CLOSE_UNSUPPORTED_COMMAND, "command not supported on this socket"
                )
            result = self.submit(command, owner=context.owner)
            if result == "unknown_endorsement":
                raise CommandRejected(CLOSE_COMMAND_CONFLICT, "unknown endorsement")
            if result == "already_resolved":
                raise CommandRejected(CLOSE_COMMAND_CONFLICT, "endorsement already resolved")

        return handle
