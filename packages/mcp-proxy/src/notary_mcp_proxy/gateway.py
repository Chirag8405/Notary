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
from notary_core.canon import sha256_hex
from notary_core.contract import assert_monotonic
from notary_core.endorsement import remaining_approvals
from notary_core.gateway import GatewayLabeler, ToolResult, ToolResultField, ValueStore
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
    EndorsementOutcome,
    EndorsementRequested,
    EndorsementResolved,
    Event,
    IntentContract,
    Label,
    Lane,
    LedgerEntry,
    NotaryModel,
    ResolvedValue,
    RunStarted,
    SessionState,
    Sha256Hex,
    ToolCallProposal,
    UserOrigin,
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
USER_VALUE_PREFIX = "request"
"""Ids of the user's own words are `request.<n>` (the engine's single request is `v-request`)."""
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
        self._user_values = 0
        self._opening: str | None = None
        self._opening_failed = False

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
        A deferred `run_started` (`defer_start`) is appended first, with the contract as it is
        now, so no event can precede it; if that append fails nothing else is appended.
        """
        if not self.ensure_started():
            return False
        event = make(self._run_id, self._lane, len(self._chain))
        try:
            self._chain = self._audit_append(self._chain, event)
        except Exception:
            self._halted = self._halted or HALT_AUDIT
            return False
        return True

    def defer_start(self, scenario: str) -> None:
        """Hold `run_started` back until the chain is first needed (`ensure_started` or `emit`).

        Until then the contract may still be replaced by `adopt_contract`. The chain must be
        empty.
        """
        if self._chain:
            raise ValueError("the run has started")
        self._opening = scenario

    def ensure_started(self) -> bool:
        """Append the deferred `run_started` (once, with the contract now in force).

        True when nothing is deferred or it was appended; False when that append failed (the
        gateway is then halted and appends nothing else).
        """
        scenario = self._opening
        if scenario is None:
            return not self._opening_failed
        self._opening = None
        try:
            event = RunStarted(
                type="run_started",
                run_id=self._run_id,
                lane=self._lane,
                seq=len(self._chain),
                scenario=scenario,
                contract=self._contract,
                classifier=None,
            )
            self._chain = self._audit_append(self._chain, event)
        except Exception:
            self._halted = self._halted or HALT_AUDIT
            self._opening_failed = True
            return False
        return True

    def adopt_contract(self, contract: IntentContract) -> None:
        """Replace the contract before the run starts; it may only narrow (I5).

        Allowed only while the chain is empty: once `run_started` is in the chain the contract is
        frozen. Raises `ValueError` after that and `ContractWideningError` when `contract` is wider
        than the one in force (`widening_reasons`, which also requires the same `contract_id` and
        `user_intent`). The pinned tools are untouched: a changed manifest hash is a widening.
        """
        if self._chain:
            raise ValueError("the contract is frozen: the run has started")
        assert_monotonic(self._contract, contract)
        self._contract = contract

    @property
    def contract(self) -> IntentContract:
        return self._contract

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

    def add_user_value(self, text: str) -> ValueRef | None:
        """Store the user's own words as a trusted value `request.<n>` (the n-th call is `.<n>`).

        The label is the engine's request label: `UserOrigin`, integrity `trusted`, readers
        `("*",)`. The `value_labeled` event is appended BEFORE the value joins the store, like every
        other value (`_add_value`), so the log shows the value before anything can use it. The
        resolver then labels an argument that equals the text, or is a span of it, `user` /
        `trusted` (its rules 1 and 2); nothing else changes.

        This is the ONLY way a trusted value joins the store at runtime. Nothing in the MCP surface
        (a tool call, a result, a resource, a prompt) reaches it: only the control socket does,
        through the worker thread that owns this Gateway. The caller decides what is "the user's
        own words" and bounds their size. Returns None when the gateway is halted or the append
        failed: nothing was stored.
        """
        if self._halted is not None:
            return None
        number = self._user_values + 1
        ref = ValueRef(
            id=f"{USER_VALUE_PREFIX}.{number}",
            label=Label(
                origin=UserOrigin(kind="user"),
                integrity="trusted",
                readers=("*",),
                span_pointer=None,
            ),
            content_hash=sha256_hex(text),
        )
        if not self._add_value(ResolvedValue(ref=ref, unit=None, text=text)):
            return None
        self._user_values = number
        return ref

    def label_content(
        self,
        source: str,
        record_id: str,
        fields: Sequence[ToolResultField],
        readers: tuple[str, ...],
    ) -> tuple[ValueRef, ...] | None:
        """Label and log content that is not a tool result (a resource, a prompt).

        There is no call and no decision: the read has no effect the monitor could judge. The
        content is labeled exactly like a read tool's result (`source` is the labeling key, so the
        origin comes from the labeling policy, else `ToolOrigin(source)`; always untrusted), every
        `value_labeled` is appended BEFORE the value joins the store, and the refs are returned so
        the caller can read the texts back from `store`. A later tool call that quotes the content
        then carries its origin.

        `record_id` must not repeat with other content (value ids are `<record_id>.<field>`; the
        same id with other content raises). Returns None when the gateway is halted or an append
        failed: nothing of the content may be handed on.
        """
        if self._halted is not None:
            return None
        values = self._labeler(
            ToolResult(tool=source, record_id=record_id, fields=tuple(fields)), readers=readers
        )
        refs: list[ValueRef] = []
        for value in values:
            if not self._add_value(value):
                return None
            refs.append(value.ref)
        return tuple(refs)

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
            if not self._resolved(endorsement_id, call_id, "rejected"):
                return self._halted_outcome(call_id)
            return self._outcome(
                call_id,
                "blocked",
                pending.decision,
                endorsement_id=endorsement_id,
                error=str(error),
            )
        # Logged before the ledger changes: an approval that is not in the chain is not applied.
        if not self._resolved(endorsement_id, call_id, "approved"):
            return self._halted_outcome(call_id)
        self._ledger = ledger
        self._session = with_approval(self._session)
        self._escalations[endorsement_id] = replace(pending, resolved=True)
        return self._decide(pending.call, pending.proposal)

    def _resolved(self, endorsement_id: str, call_id: str, outcome: EndorsementOutcome) -> bool:
        """Append `endorsement_resolved`; False when the append failed (the gateway halted)."""
        return self.emit(
            lambda run, lane, seq: EndorsementResolved(
                type="endorsement_resolved",
                run_id=run,
                lane=lane,
                seq=seq,
                endorsement_id=endorsement_id,
                call_id=call_id,
                outcome=outcome,
            )
        )

    def reject(
        self,
        endorsement_id: str,
        outcome: Literal["rejected", "timed_out", "cancelled"] = "rejected",
    ) -> MediationOutcome | None:
        """The card was not approved (`outcome` says why): no effect, no session change."""
        pending = self._escalations.get(endorsement_id)
        if pending is None or pending.resolved:
            return None
        call_id = pending.call.call_id
        if self._halted is not None:
            return self._halted_outcome(call_id)
        self._escalations[endorsement_id] = replace(pending, resolved=True)
        if not self._resolved(endorsement_id, call_id, outcome):
            return self._halted_outcome(call_id)
        return self._outcome(call_id, "blocked", pending.decision, endorsement_id=endorsement_id)
