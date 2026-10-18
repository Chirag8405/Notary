"""The Gateway: the only path from an agent to its tools.

It pins the session's tools, turns an agent's raw call into a labeled proposal, asks the monitor,
appends the decision to the audit chain BEFORE any effect, runs the tool through the injected
`ToolBackend` only on ALLOW, and labels the result. There is no network code: a real MCP transport
is P6, and a recording in-memory backend proves invariant I1 (no effect outside the adapter).

The object is deliberately mutable because it fronts I/O; every read property returns an
immutable snapshot, and the backend is private (no attribute or method hands it out).
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import Annotated, Literal, Protocol, runtime_checkable

from pydantic import Field

from notary_core.audit import append
from notary_core.endorsement import remaining_approvals
from notary_core.gateway import GatewayLabeler, ToolResult, ValueStore
from notary_core.ledger import LedgerClosureError, UserEndorsedAuthority, with_entry
from notary_core.models import (
    AuditEntry,
    CallProposed,
    Decision,
    DecisionMade,
    DecisionUnit,
    DiffCard,
    EffectExecuted,
    Endorsement,
    EndorsementRequested,
    Event,
    IntentContract,
    Lane,
    LedgerEntry,
    NotaryModel,
    ResolvedValue,
    SessionState,
    Sha256Hex,
    ToolCallProposal,
    ValueLabeled,
    ValueRef,
)
from notary_core.monitor import Monitor
from notary_core.pinning import PinReport, compare_pins, observed_hash, pin_manifests
from notary_core.policy.sensitive_params import DEFAULT_POLICY, PolicyTable, param_policy
from notary_core.resolver import ArgResolver, canonical_args
from notary_core.session import with_approval, with_effect
from notary_core.store import InMemoryValueStore
from notary_mcp_proxy.backend import BackendResult, ToolBackend

PREVIEW_LIMIT: int = 80
"""Characters kept in `ValueLabeled.preview`."""
HALT_AUDIT = "audit append failed"
ERR_EFFECT_NOT_LOGGED = "the effect ran but was not logged"
ERR_RESULT_NOT_LOGGED = "the effect ran but a result value was not logged"

AuditAppend = Callable[[Sequence[AuditEntry], Event], tuple[AuditEntry, ...]]
EventFactory = Callable[[str, Lane, int], Event]
"""Builds an event from `(run_id, lane, seq)`."""


@runtime_checkable
class ReportsAvailability(Protocol):
    """A backend that knows when its server is gone (a real transport; test doubles need not)."""

    def unavailable(self) -> str | None:
        """A constant error text when no call can reach the server, else None."""
        ...


@runtime_checkable
class ReportsToolAvailability(Protocol):
    """A backend over several servers: it knows which tool's server is gone."""

    def unavailable_for(self, tool: str) -> str | None:
        """A constant error text when `tool` cannot reach its server, else None.

        None for a tool no server owns: the scope check blocks it as usual.
        """
        ...


class ToolPin(NotaryModel):
    """A tool pinned to the hash of its manifest (description and schema)."""

    tool: str
    manifest_hash: Sha256Hex


class RawCall(NotaryModel):
    """A call as the agent typed it: raw text per parameter."""

    call_id: str
    tool: str
    args: dict[str, str]


class MediationOutcome(NotaryModel):
    call_id: str
    status: Literal["blocked", "escalated", "executed", "tool_error", "halted"]
    decision: Decision | None
    endorsement_id: str | None
    error: str | None


class PendingCard(NotaryModel):
    """A read-only snapshot of an escalated call that still waits for the user."""

    endorsement: Endorsement
    proposal: ToolCallProposal
    decision: Decision
    remaining_approvals: Annotated[int, Field(ge=0)]
    """Approvals left in the session budget now (`remaining_approvals` of the core)."""


@dataclass(frozen=True, slots=True)
class _Pending:
    """An escalated call waiting for the user. Replaced, never mutated, when it is resolved."""

    call: RawCall
    endorsement: Endorsement
    proposal: ToolCallProposal
    decision: Decision
    resolved: bool


class Gateway:
    def __init__(
        self,
        *,
        backend: ToolBackend,
        contract: IntentContract,
        ledger: Sequence[LedgerEntry],
        monitor: Monitor,
        labeler: GatewayLabeler,
        resolver: ArgResolver,
        run_id: str,
        lane: Lane = "notary",
        policy: PolicyTable = DEFAULT_POLICY,
        session: SessionState | None = None,
        store: ValueStore | None = None,
        audit_append: AuditAppend = append,
    ) -> None:
        self._backend = backend
        self._contract = contract
        self._ledger: tuple[LedgerEntry, ...] = tuple(ledger)
        self._monitor = monitor
        self._labeler = labeler
        self._resolver = resolver
        self._run_id = run_id
        self._lane: Lane = lane
        self._policy = policy
        self._session = session or SessionState(
            spent_cents=0, effects_used=0, egress_bytes_used=0, approvals_used=0
        )
        self._store: ValueStore = store if store is not None else InMemoryValueStore()
        self._audit_append = audit_append
        self._chain: tuple[AuditEntry, ...] = ()
        self._halted: str | None = None
        self._pins: dict[str, str] | None = None
        self._seen_calls: set[str] = set()
        self._escalations: dict[str, _Pending] = {}

    @property
    def chain(self) -> tuple[AuditEntry, ...]:
        return self._chain

    @property
    def store(self) -> ValueStore:
        return self._store

    @property
    def ledger(self) -> tuple[LedgerEntry, ...]:
        return self._ledger

    @property
    def session(self) -> SessionState:
        return self._session

    @property
    def halted(self) -> str | None:
        return self._halted

    def pending_endorsements(self) -> tuple[PendingCard, ...]:
        """The escalations still waiting for the user, oldest first (a snapshot; nothing leaks)."""
        left = remaining_approvals(self._contract, self._session)
        return tuple(
            PendingCard(
                endorsement=item.endorsement,
                proposal=item.proposal,
                decision=item.decision,
                remaining_approvals=left,
            )
            for item in self._escalations.values()
            if not item.resolved
        )

    def emit(self, make: EventFactory) -> bool:
        """Append one event; a failing append halts the gateway and leaves the chain unchanged.

        The runner uses this for `run_started`, `oracle_updated` and `run_finished`. It still
        tries to append after a halt (a `run_finished` is worth logging), but never retries.
        """
        event = make(self._run_id, self._lane, len(self._chain))
        try:
            self._chain = self._audit_append(self._chain, event)
        except Exception:
            self._halted = self._halted or HALT_AUDIT
            return False
        return True

    def pin_session(self) -> tuple[ToolPin, ...]:
        """Pin every tool the backend reports now; calling it again re-pins."""
        pins = pin_manifests(self._backend.list_tools())
        self._pins = pins
        return tuple(ToolPin(tool=tool, manifest_hash=digest) for tool, digest in pins.items())

    def check_drift(self) -> PinReport:
        """Compare the pins with what the backend reports now (drift is a rug pull, A10)."""
        if self._pins is None:
            raise ValueError("session is not pinned")
        return compare_pins(self._pins, self._backend.list_tools())

    def _halted_outcome(self, call_id: str, error: str | None = None) -> MediationOutcome:
        return MediationOutcome(
            call_id=call_id,
            status="halted",
            decision=None,
            endorsement_id=None,
            error=error or self._halted,
        )

    def propose(self, call: RawCall) -> MediationOutcome:
        """Label the arguments, propose, decide (write-ahead) and run the tool only on ALLOW."""
        if self._halted is not None:
            return self._halted_outcome(call.call_id)
        gone: str | None = None
        if isinstance(self._backend, ReportsToolAvailability):
            gone = self._backend.unavailable_for(call.tool)
        if gone is None and isinstance(self._backend, ReportsAvailability):
            gone = self._backend.unavailable()
        if gone is not None:
            # Answered before anything is resolved or proposed: the chain does not change.
            return MediationOutcome(
                call_id=call.call_id,
                status="tool_error",
                decision=None,
                endorsement_id=None,
                error=gone,
            )
        if call.call_id in self._seen_calls:
            raise ValueError("duplicate call id")
        self._seen_calls.add(call.call_id)
        refs: dict[str, ValueRef] = {}
        for param in sorted(call.args):
            value = self._resolver(
                call_id=call.call_id,
                tool=call.tool,
                param=param,
                raw=call.args[param],
                unit=param_policy(self._policy, call.tool, param).unit,
                store=self._store.as_mapping(),
            )
            if not self._add_value(value):
                return self._halted_outcome(call.call_id)
            refs[param] = value.ref
        # The hash is what the backend reports now, never the agent's claim.
        proposal = ToolCallProposal(
            call_id=call.call_id,
            tool=call.tool,
            manifest_hash=observed_hash(self._backend.list_tools(), call.tool),
            args=refs,
        )
        proposed = self.emit(
            lambda run, lane, seq: CallProposed(
                type="call_proposed", run_id=run, lane=lane, seq=seq, proposal=proposal
            )
        )
        if not proposed:
            return self._halted_outcome(call.call_id)
        return self._decide(call, proposal)

    def _add_value(self, value: ResolvedValue) -> bool:
        """Announce and store a value; it joins the store only after its event is appended."""
        known = self._store.get(value.ref.id)
        if known is not None:
            if known != value:
                raise ValueError("value id collision")
            return True
        logged = self.emit(
            lambda run, lane, seq: ValueLabeled(
                type="value_labeled",
                run_id=run,
                lane=lane,
                seq=seq,
                value=value.ref,
                unit=value.unit,
                preview=value.text[:PREVIEW_LIMIT],
            )
        )
        if not logged:
            return False
        self._store = self._store.with_values([value])
        return True

    def _decide(self, call: RawCall, proposal: ToolCallProposal) -> MediationOutcome:
        """Ask the monitor, append the decision FIRST, then act on it."""
        decision = self._monitor(
            self._contract, proposal, self._store.as_mapping(), self._ledger, self._session
        )
        decided = self.emit(
            lambda run, lane, seq: DecisionMade(
                type="decision_made",
                run_id=run,
                lane=lane,
                seq=seq,
                call_id=proposal.call_id,
                decision=decision,
            )
        )
        if not decided:
            return self._halted_outcome(call.call_id)
        if decision.verdict == "BLOCK":
            return self._outcome(call.call_id, "blocked", decision)
        if decision.verdict == "ESCALATE":
            return self._escalate(call, proposal, decision)
        return self._execute(call, proposal, decision)

    def _outcome(
        self,
        call_id: str,
        status: Literal["blocked", "escalated", "executed", "tool_error"],
        decision: Decision,
        *,
        endorsement_id: str | None = None,
        error: str | None = None,
    ) -> MediationOutcome:
        return MediationOutcome(
            call_id=call_id,
            status=status,
            decision=decision,
            endorsement_id=endorsement_id,
            error=error,
        )

    def _escalate(
        self, call: RawCall, proposal: ToolCallProposal, decision: Decision
    ) -> MediationOutcome:
        k = len(self._escalations) + 1
        endorsement_id = f"e{k}"
        endorsement = Endorsement(
            endorsement_id=endorsement_id,
            call_id=call.call_id,
            card=decision.diff_card or DiffCard(rows=()),
            status="pending",
            sequence=k - 1,
        )
        self._escalations[endorsement_id] = _Pending(
            call=call, endorsement=endorsement, proposal=proposal, decision=decision, resolved=False
        )
        requested = self.emit(
            lambda run, lane, seq: EndorsementRequested(
                type="endorsement_requested",
                run_id=run,
                lane=lane,
                seq=seq,
                endorsement=endorsement,
            )
        )
        if not requested:
            return self._halted_outcome(call.call_id)
        return self._outcome(call.call_id, "escalated", decision, endorsement_id=endorsement_id)

    def _execute(
        self, call: RawCall, proposal: ToolCallProposal, decision: Decision
    ) -> MediationOutcome:
        """The only place the backend runs a tool; reached only after a logged ALLOW."""
        resolved: dict[str, ResolvedValue] = {}
        for param, ref in sorted(proposal.args.items()):
            value = self._store.get(ref.id)
            if value is None:
                raise ValueError("judged value missing from the store")
            resolved[param] = value
        units: dict[str, DecisionUnit | None] = {
            param: param_policy(self._policy, call.tool, param).unit for param in resolved
        }
        result = self._backend.call_tool(call.tool, canonical_args(resolved, units))
        if result.error is not None:
            # No effect and no spend, but whatever the server said is still labeled and logged
            # before the caller can show it.
            if not self._label_records(call, result):
                return self._halted_outcome(call.call_id, ERR_RESULT_NOT_LOGGED)
            return self._outcome(call.call_id, "tool_error", decision, error=result.error)
        effect = result.effect
        # The session update is committed before the effect is logged: if that append fails the
        # effect really happened, so the update stays.
        if effect is not None and effect.mutating:
            self._session = with_effect(
                self._session, spent_cents=effect.spent_cents, egress_bytes=effect.egress_bytes
            )
        if effect is not None:
            summary = effect.summary
            logged = self.emit(
                lambda run, lane, seq: EffectExecuted(
                    type="effect_executed",
                    run_id=run,
                    lane=lane,
                    seq=seq,
                    call_id=call.call_id,
                    tool=call.tool,
                    summary=summary,
                )
            )
            if not logged:
                return self._halted_outcome(call.call_id, ERR_EFFECT_NOT_LOGGED)
        if not self._label_records(call, result):
            return self._halted_outcome(call.call_id, ERR_RESULT_NOT_LOGGED)
        return self._outcome(call.call_id, "executed", decision)

    def _label_records(self, call: RawCall, result: BackendResult) -> bool:
        """Label and log every result field; False when an append failed (the gateway halted)."""
        for record in result.records:
            labeled = self._labeler(
                ToolResult(
                    tool=call.tool,
                    record_id=f"{call.call_id}.{record.record_id}",
                    fields=record.fields,
                ),
                readers=record.readers,
            )
            for value in labeled:
                if not self._add_value(value):
                    return False
        return True

    def approve(
        self, endorsement_id: str, entries: Sequence[LedgerEntry]
    ) -> MediationOutcome | None:
        """The user approved: write ALL entries or none, then decide the same proposal again."""
        pending = self._escalations.get(endorsement_id)
        if pending is None or pending.resolved:
            return None
        call_id = pending.call.call_id
        if self._halted is not None:
            return self._halted_outcome(call_id)
        authority = UserEndorsedAuthority(kind="user_endorsed", endorsement_id=endorsement_id)
        ledger = self._ledger
        try:
            for entry in entries:
                ledger = with_entry(ledger, entry, authority)
        except LedgerClosureError as error:
            self._escalations[endorsement_id] = replace(pending, resolved=True)
            return self._outcome(
                call_id,
                "blocked",
                pending.decision,
                endorsement_id=endorsement_id,
                error=str(error),
            )
        self._ledger = ledger
        self._session = with_approval(self._session)
        self._escalations[endorsement_id] = replace(pending, resolved=True)
        return self._decide(pending.call, pending.proposal)

    def reject(self, endorsement_id: str) -> MediationOutcome | None:
        """The user rejected: no effect, no session change."""
        pending = self._escalations.get(endorsement_id)
        if pending is None or pending.resolved:
            return None
        call_id = pending.call.call_id
        if self._halted is not None:
            return self._halted_outcome(call_id)
        self._escalations[endorsement_id] = replace(pending, resolved=True)
        return self._outcome(call_id, "blocked", pending.decision, endorsement_id=endorsement_id)
