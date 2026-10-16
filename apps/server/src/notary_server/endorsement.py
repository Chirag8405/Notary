"""The Endorsement Service: the human-in-the-loop decider for ESCALATE.

The agent runner stops at an escalation and asks a decider. The decider published here registers
the pending diff card, blocks the runner's worker thread, and returns whatever the user's
`endorsement_decision` command said. It never approves anything by itself: the only path to
"approve" is an accepted `approve` command for exactly that run and endorsement. A timeout, a
cancelled run or a disconnect all reject (fail closed). The ledger write itself is the engine's
(`resolve_escalation`, authority `user_endorsed`); this module only carries the decision.
"""

import threading
import time
from collections import OrderedDict
from typing import Literal

from notary_core.endorsement import render_card
from notary_core.models import Command, Endorsement, EndorsementDecisionCommand, NotaryModel
from notary_server.agent_runner import EscalationDecider
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

Decision = Literal["approve", "reject"]


class PendingEndorsement(NotaryModel):
    run_id: str
    endorsement: Endorsement
    card_text: str
    """`render_card(endorsement.card)`: built from labels only, never from agent prose."""
    remaining_approvals: int
    """`max_approvals` minus the approvals accepted so far for this run, when registered."""


class PendingList(NotaryModel):
    pending: tuple[PendingEndorsement, ...]


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


class EndorsementBroker:
    def __init__(self, *, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout_seconds
        self._cond = threading.Condition()
        self._runs: OrderedDict[str, _Run] = OrderedDict()

    def decider_for(self, run_id: str, *, max_approvals: int) -> EscalationDecider:
        """The decider of one run. Calling it starts the run: state left by an earlier run with
        the same id is rejected and dropped, so a stale decision can never answer a new run."""
        with self._cond:
            previous = self._runs.pop(run_id, None)
            if previous is not None:
                previous.reject_unresolved()
                self._cond.notify_all()
            self._runs[run_id] = _Run()
            self._evict()

        def decide(endorsement: Endorsement) -> Decision:
            return self._wait(run_id, endorsement, max_approvals)

        return decide

    def _evict(self) -> None:
        for old_id in list(self._runs):
            if len(self._runs) <= MAX_RUNS:
                return
            if not self._runs[old_id].has_waiter():
                del self._runs[old_id]

    def _wait(self, run_id: str, endorsement: Endorsement, max_approvals: int) -> Decision:
        with self._cond:
            run = self._runs.setdefault(run_id, _Run())
            slot = run.slots.get(endorsement.endorsement_id)
            if slot is None:
                remaining = max(max_approvals - run.approved, 0)
                slot = _Slot(endorsement, remaining)
                run.slots[endorsement.endorsement_id] = slot
                if run.cancelled:
                    slot.decision = "reject"
            deadline = time.monotonic() + self._timeout
            while slot.decision is None:
                left = deadline - time.monotonic()
                if left <= 0:
                    slot.decision = "reject"
                    break
                self._cond.wait(left)
            return slot.decision

    def submit(self, command: EndorsementDecisionCommand) -> SubmitResult:
        with self._cond:
            run = self._runs.get(command.run_id)
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

    def pending(self, run_id: str) -> tuple[PendingEndorsement, ...]:
        with self._cond:
            run = self._runs.get(run_id)
            if run is None:
                return ()
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

    def cancel_run(self, run_id: str) -> None:
        """Reject every unresolved slot of the run; a later escalation of it is rejected at once."""
        with self._cond:
            run = self._runs.get(run_id)
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
            result = self.submit(command)
            if result == "unknown_endorsement":
                raise CommandRejected(CLOSE_COMMAND_CONFLICT, "unknown endorsement")
            if result == "already_resolved":
                raise CommandRejected(CLOSE_COMMAND_CONFLICT, "endorsement already resolved")

        return handle
