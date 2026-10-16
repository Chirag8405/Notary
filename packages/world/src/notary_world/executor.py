"""Run executor and Hijacked Mode runner: raw tool calls through the monitor, no LLM involved.

Each call goes label -> monitor -> write-ahead audit entry -> world tool (only on ALLOW) -> label
the result. The `RunRecord` it returns is what the oracle, the fuzz harness, the CLI and the attack
fixtures consume. Every operation is a pure function of an immutable `RunEngine`.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Literal, Protocol

from notary_core.audit import append
from notary_core.canon import sha256_hex
from notary_core.contract import ContractWideningError, assert_monotonic
from notary_core.gateway import GatewayLabeler
from notary_core.ledger import (
    LedgerClosureError,
    UserEndorsedAuthority,
    WriteAuthority,
    with_entry,
)
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
    HijackedToolCallCommand,
    IntentContract,
    Label,
    Lane,
    LedgerEntry,
    LlmOrigin,
    NotaryModel,
    OracleResult,
    OracleUpdated,
    ResolvedValue,
    RunFinished,
    RunStarted,
    SessionState,
    SpanPointer,
    ToolCallProposal,
    UserEndorsedSource,
    UserOrigin,
    ValueLabeled,
    ValueRef,
)
from notary_core.monitor import Monitor, decide
from notary_core.policy.sensitive_params import PolicyTable
from notary_core.provenance import INTEGRITY_ORDER, join_all_readers, normalize_readers
from notary_core.session import with_approval, with_effect
from notary_core.units import canonicalize
from notary_world.fakes import FakeGateway
from notary_world.scenarios import Scenario
from notary_world.state import WorldDiff, WorldState, diff
from notary_world.tools import (
    EffectRecord,
    RawToolCall,
    as_gateway_results,
    param_unit,
    tool_manifest_hash,
    world_policy,
)
from notary_world.tools import call as call_tool

MIN_MATCH_LEN: int = 4
"""Shortest text the resolver matches inside a stored value."""
PREVIEW_LIMIT: int = 80
"""Characters kept in `ValueLabeled.preview`."""
MAX_ESCALATION_ROUNDS: int = 8
"""Approvals `execute_run` applies to one call; any further escalation of it is rejected."""
ERR_UNKNOWN_ENDORSEMENT = "endorsement was not approved"
ERR_BAD_APPROVAL_ROW = "approval row does not match the proposal"
HALT_AUDIT = "audit append failed"
REQUEST_VALUE_ID = "v-request"

AuditAppend = Callable[[Sequence[AuditEntry], Event], tuple[AuditEntry, ...]]
"""Appends one event to the audit chain; the default is `notary_core.audit.append`."""


class ArgResolver(Protocol):
    """Labels the raw text of one argument (stand-in for the P3a Gateway argument labeling)."""

    def __call__(
        self,
        *,
        call_id: str,
        tool: str,
        param: str,
        raw: str,
        unit: DecisionUnit | None,
        store: Mapping[str, ResolvedValue],
    ) -> ResolvedValue: ...


class ScriptedApprovals(NotaryModel):
    approve: tuple[str, ...]
    """Call ids the scripted user approves; every other escalation is rejected."""


EscalationMode = Literal["reject", "approve_all"] | ScriptedApprovals

CallStatus = Literal["blocked", "escalated", "executed", "tool_error"]


class ArgRecord(NotaryModel):
    param: str
    value: ResolvedValue


class DecisionInputs(NotaryModel):
    """Everything the monitor saw, so a decision can be replayed."""

    contract: IntentContract
    proposal: ToolCallProposal
    values: tuple[ResolvedValue, ...]
    """The whole store, sorted by `ref.id`."""
    ledger: tuple[LedgerEntry, ...]
    session: SessionState


class CallRecord(NotaryModel):
    call_id: str
    phase: Literal["initial", "after_approval"]
    tool: str
    args: tuple[ArgRecord, ...]
    """Sorted by param."""
    inputs: DecisionInputs
    decision: Decision
    status: CallStatus
    effect: EffectRecord | None
    error: str | None
    decision_index: int
    """Chain index of the `decision_made` entry."""
    effect_index: int | None
    """Chain index of the `effect_executed` entry; None when there is none."""


class EscalationRecord(NotaryModel):
    endorsement_id: str
    call_id: str
    resolution: Literal["pending", "approved", "rejected"]
    ledger_entry_ids: tuple[str, ...]


class LedgerSnapshot(NotaryModel):
    step: int
    cause: Literal["initial", "approval", "user_write"]
    ledger: tuple[LedgerEntry, ...]


class ContractSnapshot(NotaryModel):
    step: int
    cause: Literal["initial", "update"]
    contract: IntentContract


class RefusalRecord(NotaryModel):
    step: int
    kind: Literal["ledger_write", "contract_update"]
    reason: str
    """An ERR_* constant, a `LedgerClosureError` message, or sorted widening reasons."""


class CallOutcome(NotaryModel):
    call_id: str
    status: Literal["blocked", "escalated", "executed", "tool_error", "halted"]
    decision: Decision | None
    endorsement_id: str | None
    error: str | None


class RunRecord(NotaryModel):
    run_id: str
    lane: Lane
    scenario: str
    user_request: str
    world_before: WorldState
    world_after: WorldState
    world_diff: WorldDiff
    chain: tuple[AuditEntry, ...]
    calls: tuple[CallRecord, ...]
    escalations: tuple[EscalationRecord, ...]
    contract_snapshots: tuple[ContractSnapshot, ...]
    ledger_snapshots: tuple[LedgerSnapshot, ...]
    refusals: tuple[RefusalRecord, ...]
    values: tuple[ResolvedValue, ...]
    """The final store, sorted by `ref.id`."""
    session: SessionState
    halted: str | None

    @property
    def events(self) -> tuple[Event, ...]:
        return tuple(entry.event for entry in self.chain)


OracleFn = Callable[[RunRecord], OracleResult]


def _rank(value: ResolvedValue) -> tuple[int, str]:
    """Lowest integrity first, then the smallest id."""
    return (INTEGRITY_ORDER.index(value.ref.label.integrity), value.ref.id)


def _same_value(value: ResolvedValue, raw: str, unit: DecisionUnit | None) -> bool:
    if value.text.strip() == raw.strip():
        return True
    return (
        unit is not None and canonicalize(unit, value.text).value == canonicalize(unit, raw).value
    )


class DefaultArgResolver:
    """Stand-in for the P3a Gateway argument labeling; same call signature as `ArgResolver`.

    Rule 1 reuses a stored value with the same text or canonical form, Rule 2 labels a span of a
    stored value with that value's label, Rule 3 labels anything else as model-authored text.
    Known limit: a secret is detected only when it is quoted whole or when the raw text is a
    substring of one stored value; encoded or mixed text gets public readers. The real Gateway
    replaces this behind the same protocol.
    """

    def __call__(
        self,
        *,
        call_id: str,
        tool: str,
        param: str,
        raw: str,
        unit: DecisionUnit | None,
        store: Mapping[str, ResolvedValue],
    ) -> ResolvedValue:
        values = sorted(store.values(), key=lambda v: v.ref.id)
        same = [v for v in values if _same_value(v, raw, unit)]
        if same:
            return min(same, key=_rank)
        value_id = f"{call_id}.arg.{param}"
        text = raw.strip()
        if len(text) >= MIN_MATCH_LEN:
            containing = [v for v in values if text in v.text]
            if containing:
                source = min(containing, key=_rank)
                start = source.text.index(text)
                label = Label(
                    origin=source.ref.label.origin,
                    integrity=source.ref.label.integrity,
                    readers=source.ref.label.readers,
                    span_pointer=SpanPointer(
                        source_value_id=source.ref.id, start=start, end=start + len(text)
                    ),
                )
                ref = ValueRef(id=value_id, label=label, content_hash=sha256_hex(text))
                return ResolvedValue(ref=ref, unit=unit, text=text)
        readers = normalize_readers(
            join_all_readers(
                v.ref.label.readers
                for v in values
                if len(v.text.strip()) >= MIN_MATCH_LEN and v.text.strip() in raw
            )
        )
        label = Label(
            origin=LlmOrigin(kind="llm"), integrity="untrusted", readers=readers, span_pointer=None
        )
        ref = ValueRef(id=value_id, label=label, content_hash=sha256_hex(raw))
        return ResolvedValue(ref=ref, unit=unit, text=raw)


PendingEscalation = tuple[str, RawToolCall, ToolCallProposal]
EventFactory = Callable[[str, Lane, int], Event]
"""Builds an event from `(run_id, lane, seq)`."""


@dataclass(frozen=True, slots=True)
class RunEngine:
    """Immutable run state; every operation returns a new engine."""

    run_id: str
    lane: Lane
    scenario: str
    request: str
    world_before: WorldState
    world: WorldState
    contract: IntentContract
    ledger: tuple[LedgerEntry, ...]
    session: SessionState
    store: tuple[ResolvedValue, ...]
    """Sorted by `ref.id`."""
    chain: tuple[AuditEntry, ...]
    calls: tuple[CallRecord, ...]
    escalations: tuple[EscalationRecord, ...]
    pending: tuple[PendingEscalation, ...]
    contract_snapshots: tuple[ContractSnapshot, ...]
    ledger_snapshots: tuple[LedgerSnapshot, ...]
    refusals: tuple[RefusalRecord, ...]
    step: int
    halted: str | None
    finished: bool
    monitor: Monitor
    gateway: GatewayLabeler
    resolver: ArgResolver
    audit_append: AuditAppend


def default_monitor(policy: PolicyTable | None = None) -> Monitor:
    """The real `decide`, with `world_policy()` unless a policy table is given."""
    table = world_policy() if policy is None else policy

    def monitor(
        contract: IntentContract,
        proposal: ToolCallProposal,
        values: Mapping[str, ResolvedValue],
        ledger: Sequence[LedgerEntry],
        session: SessionState,
    ) -> Decision:
        return decide(contract, proposal, values, ledger, session, policy=table)

    return monitor


def _emit(engine: RunEngine, make: EventFactory) -> RunEngine:
    """Append one event; a failing append halts the engine and leaves the chain unchanged."""
    event = make(engine.run_id, engine.lane, len(engine.chain))
    try:
        chain = engine.audit_append(engine.chain, event)
    except Exception:
        return replace(engine, halted=engine.halted or HALT_AUDIT)
    return replace(engine, chain=chain)


def _store_dict(engine: RunEngine) -> dict[str, ResolvedValue]:
    """A fresh mapping in id order; the engine's tuple is never exposed."""
    return {v.ref.id: v for v in engine.store}


def _lookup(engine: RunEngine, value_id: str) -> ResolvedValue | None:
    return next((v for v in engine.store if v.ref.id == value_id), None)


def _add_value(engine: RunEngine, value: ResolvedValue) -> RunEngine:
    """Announce and store a value; a value joins the store only after its event is appended."""
    existing = _lookup(engine, value.ref.id)
    if existing is not None:
        if existing != value:
            raise ValueError("value id collision")
        return engine

    def make(run_id: str, lane: Lane, seq: int) -> Event:
        return ValueLabeled(
            type="value_labeled",
            run_id=run_id,
            lane=lane,
            seq=seq,
            value=value.ref,
            unit=value.unit,
            preview=value.text[:PREVIEW_LIMIT],
        )

    emitted = _emit(engine, make)
    if emitted.halted is not None:
        return emitted
    store = tuple(sorted((*engine.store, value), key=lambda v: v.ref.id))
    return replace(emitted, store=store)


def start_run(
    *,
    run_id: str,
    scenario: str,
    request: str,
    world: WorldState,
    contract: IntentContract,
    ledger: Sequence[LedgerEntry],
    session: SessionState | None = None,
    lane: Lane = "notary",
    monitor: Monitor | None = None,
    gateway: GatewayLabeler | None = None,
    resolver: ArgResolver | None = None,
    audit_append: AuditAppend = append,
) -> RunEngine:
    """A new engine with the user request stored and `run_started` as chain entry 0."""
    request_value = ResolvedValue(
        ref=ValueRef(
            id=REQUEST_VALUE_ID,
            label=Label(
                origin=UserOrigin(kind="user"),
                integrity="trusted",
                readers=("*",),
                span_pointer=None,
            ),
            content_hash=sha256_hex(request),
        ),
        unit=None,
        text=request,
    )
    entries = tuple(ledger)
    engine = RunEngine(
        run_id=run_id,
        lane=lane,
        scenario=scenario,
        request=request,
        world_before=world,
        world=world,
        contract=contract,
        ledger=entries,
        session=session
        or SessionState(spent_cents=0, effects_used=0, egress_bytes_used=0, approvals_used=0),
        store=(request_value,),
        chain=(),
        calls=(),
        escalations=(),
        pending=(),
        contract_snapshots=(ContractSnapshot(step=0, cause="initial", contract=contract),),
        ledger_snapshots=(LedgerSnapshot(step=0, cause="initial", ledger=entries),),
        refusals=(),
        step=0,
        halted=None,
        finished=False,
        monitor=monitor or default_monitor(),
        gateway=gateway or FakeGateway(),
        resolver=resolver or DefaultArgResolver(),
        audit_append=audit_append,
    )
    return _emit(
        engine,
        lambda run, lane_, seq: RunStarted(
            type="run_started",
            run_id=run,
            lane=lane_,
            seq=seq,
            scenario=scenario,
            contract=contract,
            classifier=None,
        ),
    )


def _halted(call_id: str, engine: RunEngine, decision: Decision | None = None) -> CallOutcome:
    return CallOutcome(
        call_id=call_id,
        status="halted",
        decision=decision,
        endorsement_id=None,
        error=engine.halted,
    )


def _inputs(engine: RunEngine, proposal: ToolCallProposal) -> DecisionInputs:
    return DecisionInputs(
        contract=engine.contract,
        proposal=proposal,
        values=engine.store,
        ledger=engine.ledger,
        session=engine.session,
    )


def _arg_records(engine: RunEngine, proposal: ToolCallProposal) -> tuple[ArgRecord, ...]:
    out: list[ArgRecord] = []
    for param, ref in sorted(proposal.args.items()):
        value = _lookup(engine, ref.id)
        if value is not None:
            out.append(ArgRecord(param=param, value=value))
    return tuple(out)


def _decide(
    engine: RunEngine, proposal: ToolCallProposal
) -> tuple[RunEngine, DecisionInputs, Decision, int]:
    """Ask the monitor and append `decision_made` (write-ahead); halts if the append fails."""
    inputs = _inputs(engine, proposal)
    decision = engine.monitor(
        engine.contract, proposal, _store_dict(engine), engine.ledger, engine.session
    )
    decision_index = len(engine.chain)
    engine = _emit(
        engine,
        lambda run, lane, seq: DecisionMade(
            type="decision_made",
            run_id=run,
            lane=lane,
            seq=seq,
            call_id=proposal.call_id,
            decision=decision,
        ),
    )
    return engine, inputs, decision, decision_index


@dataclass(frozen=True, slots=True)
class _Judged:
    """A decided proposal whose `decision_made` entry is already in the chain."""

    call: RawToolCall
    proposal: ToolCallProposal
    phase: Literal["initial", "after_approval"]
    inputs: DecisionInputs
    decision: Decision
    decision_index: int

    def outcome(
        self,
        status: CallStatus,
        *,
        endorsement_id: str | None = None,
        error: str | None = None,
    ) -> CallOutcome:
        return CallOutcome(
            call_id=self.proposal.call_id,
            status=status,
            decision=self.decision,
            endorsement_id=endorsement_id,
            error=error,
        )


def _record(
    engine: RunEngine,
    judged: _Judged,
    status: CallStatus,
    *,
    effect: EffectRecord | None = None,
    error: str | None = None,
    effect_index: int | None = None,
) -> RunEngine:
    record = CallRecord(
        call_id=judged.proposal.call_id,
        phase=judged.phase,
        tool=judged.proposal.tool,
        args=_arg_records(engine, judged.proposal),
        inputs=judged.inputs,
        decision=judged.decision,
        status=status,
        effect=effect,
        error=error,
        decision_index=judged.decision_index,
        effect_index=effect_index,
    )
    return replace(engine, calls=(*engine.calls, record))


def _escalate(engine: RunEngine, judged: _Judged) -> tuple[RunEngine, CallOutcome]:
    """Record the escalation as pending, then announce it."""
    call_id = judged.proposal.call_id
    k = len(engine.escalations) + 1
    endorsement_id = f"e{k}"
    endorsement = Endorsement(
        endorsement_id=endorsement_id,
        call_id=call_id,
        card=judged.decision.diff_card or DiffCard(rows=()),
        status="pending",
        sequence=k - 1,
    )
    escalation = EscalationRecord(
        endorsement_id=endorsement_id, call_id=call_id, resolution="pending", ledger_entry_ids=()
    )
    engine = replace(
        engine,
        escalations=(*engine.escalations, escalation),
        pending=(*engine.pending, (endorsement_id, judged.call, judged.proposal)),
    )
    engine = _emit(
        engine,
        lambda run, lane, seq: EndorsementRequested(
            type="endorsement_requested",
            run_id=run,
            lane=lane,
            seq=seq,
            endorsement=endorsement,
        ),
    )
    if engine.halted is not None:
        return engine, _halted(call_id, engine, judged.decision)
    return engine, judged.outcome("escalated", endorsement_id=endorsement_id)


def _execute(engine: RunEngine, judged: _Judged) -> tuple[RunEngine, CallOutcome]:
    """Run the world tool on exactly the texts the monitor judged, then label its output."""
    proposal = judged.proposal
    call_id = proposal.call_id
    args: dict[str, str] = {}
    for param, ref in sorted(proposal.args.items()):
        value = _lookup(engine, ref.id)
        if value is None:
            raise ValueError("judged value missing from the store")
        args[param] = value.text
    result = call_tool(engine.world, proposal.tool, args)
    if result.error is not None:
        engine = _record(engine, judged, "tool_error", error=result.error)
        return engine, judged.outcome("tool_error", error=result.error)
    effect = result.effect
    session = engine.session
    if effect is not None and effect.effect != "read":
        session = with_effect(
            session, spent_cents=effect.spent_cents, egress_bytes=effect.egress_bytes
        )
    # The world change, the session update and the call record are committed together; a failed
    # `effect_executed` append cannot undo an effect that really happened, so it only halts.
    engine = replace(engine, world=result.new_state, session=session)
    if effect is None:
        engine = _record(engine, judged, "executed")
    else:
        effect_index = len(engine.chain)
        summary = effect.summary
        engine = _emit(
            engine,
            lambda run, lane, seq: EffectExecuted(
                type="effect_executed",
                run_id=run,
                lane=lane,
                seq=seq,
                call_id=call_id,
                tool=proposal.tool,
                summary=summary,
            ),
        )
        engine = _record(
            engine,
            judged,
            "executed",
            effect=effect,
            effect_index=None if engine.halted is not None else effect_index,
        )
    for core_result, readers in as_gateway_results(call_id, result):
        for value in engine.gateway(core_result, readers=readers):
            if engine.halted is not None:
                break
            engine = _add_value(engine, value)
    if engine.halted is not None:
        return engine, _halted(call_id, engine, judged.decision)
    return engine, judged.outcome("executed")


def _apply(engine: RunEngine, judged: _Judged) -> tuple[RunEngine, CallOutcome]:
    """Act on a recorded decision: BLOCK records, ESCALATE asks the user, ALLOW executes."""
    match judged.decision.verdict:
        case "BLOCK":
            engine = _record(engine, judged, "blocked")
            return engine, judged.outcome("blocked")
        case "ESCALATE":
            engine = _record(engine, judged, "escalated")
            return _escalate(engine, judged)
        case "ALLOW":
            return _execute(engine, judged)


def _judge(
    engine: RunEngine,
    call: RawToolCall,
    proposal: ToolCallProposal,
    phase: Literal["initial", "after_approval"],
) -> tuple[RunEngine, CallOutcome]:
    """Decide, append the decision write-ahead, then act on it; no tool runs if the append fails."""
    engine, inputs, decision, decision_index = _decide(engine, proposal)
    if engine.halted is not None:
        return engine, _halted(proposal.call_id, engine)
    judged = _Judged(
        call=call,
        proposal=proposal,
        phase=phase,
        inputs=inputs,
        decision=decision,
        decision_index=decision_index,
    )
    return _apply(engine, judged)


def _check_open(engine: RunEngine) -> None:
    if engine.finished:
        raise ValueError("run already finished")


def propose(engine: RunEngine, call: RawToolCall) -> tuple[RunEngine, CallOutcome]:
    """Label the arguments, propose, decide (write-ahead) and run the tool only on ALLOW."""
    if engine.halted is not None:
        return engine, _halted(call.call_id, engine)
    _check_open(engine)
    if any(record.call_id == call.call_id for record in engine.calls):
        raise ValueError("duplicate call id")
    engine = replace(engine, step=engine.step + 1)
    refs: dict[str, ValueRef] = {}
    for param, raw in sorted(call.args.items()):
        value = engine.resolver(
            call_id=call.call_id,
            tool=call.tool,
            param=param,
            raw=raw,
            unit=param_unit(call.tool, param),
            store=_store_dict(engine),
        )
        engine = _add_value(engine, value)
        if engine.halted is not None:
            return engine, _halted(call.call_id, engine)
        refs[param] = value.ref
    proposal = ToolCallProposal(
        call_id=call.call_id,
        tool=call.tool,
        manifest_hash=tool_manifest_hash(engine.world, call.tool),
        args=refs,
    )
    engine = _emit(
        engine,
        lambda run, lane, seq: CallProposed(
            type="call_proposed", run_id=run, lane=lane, seq=seq, proposal=proposal
        ),
    )
    if engine.halted is not None:
        return engine, _halted(call.call_id, engine)
    return _judge(engine, call, proposal, "initial")


def _set_resolution(
    engine: RunEngine,
    endorsement_id: str,
    resolution: Literal["approved", "rejected"],
    ledger_entry_ids: tuple[str, ...] = (),
) -> RunEngine:
    escalations = tuple(
        e.model_copy(update={"resolution": resolution, "ledger_entry_ids": ledger_entry_ids})
        if e.endorsement_id == endorsement_id
        else e
        for e in engine.escalations
    )
    pending = tuple(p for p in engine.pending if p[0] != endorsement_id)
    return replace(engine, escalations=escalations, pending=pending)


def _escalated_decision(engine: RunEngine, call_id: str) -> Decision:
    """The ESCALATE decision of the call's latest record."""
    return next(r.decision for r in reversed(engine.calls) if r.call_id == call_id)


def _approval_entries(
    engine: RunEngine, endorsement_id: str, proposal: ToolCallProposal, card: DiffCard
) -> tuple[LedgerEntry, ...] | str:
    """The ledger entries of an approved card, or the refusal reason. All rows or none."""
    entries: list[LedgerEntry] = []
    for row in card.rows:
        ref = proposal.args.get(row.param)
        value = None if ref is None else _lookup(engine, ref.id)
        if value is None:
            return ERR_BAD_APPROVAL_ROW
        unit: DecisionUnit = param_unit(proposal.tool, row.param) or "identifier"
        entries.append(
            LedgerEntry(
                entry_id=f"led-{endorsement_id}-{row.param}",
                ledger="endorsed",
                key=f"{row.param}: {row.preview}",
                value=value.ref,
                unit=unit,
                canonical=row.preview,
                source=UserEndorsedSource(kind="user_endorsed", endorsement_id=endorsement_id),
            )
        )
    return tuple(entries)


def resolve_escalation(
    engine: RunEngine, endorsement_id: str, decision: Literal["approve", "reject"]
) -> tuple[RunEngine, CallOutcome | None]:
    """Reject, or approve (endorse into the ledger, then decide the same proposal again)."""
    _check_open(engine)
    if engine.halted is not None:
        return engine, None
    found = next((p for p in engine.pending if p[0] == endorsement_id), None)
    if found is None:
        return engine, None
    _, call, proposal = found
    escalated = _escalated_decision(engine, proposal.call_id)
    engine = replace(engine, step=engine.step + 1)
    blocked = CallOutcome(
        call_id=proposal.call_id,
        status="blocked",
        decision=escalated,
        endorsement_id=endorsement_id,
        error=None,
    )
    if decision == "reject":
        return _set_resolution(engine, endorsement_id, "rejected"), blocked
    built = _approval_entries(
        engine, endorsement_id, proposal, escalated.diff_card or DiffCard(rows=())
    )
    ledger = engine.ledger
    reason: str | None = built if isinstance(built, str) else None
    if not isinstance(built, str):
        authority = UserEndorsedAuthority(kind="user_endorsed", endorsement_id=endorsement_id)
        try:
            for entry in built:
                ledger = with_entry(ledger, entry, authority)
        except LedgerClosureError as error:
            reason = str(error)
    if reason is not None:
        refusal = RefusalRecord(step=engine.step, kind="ledger_write", reason=reason)
        engine = replace(engine, refusals=(*engine.refusals, refusal))
        return _set_resolution(engine, endorsement_id, "rejected"), blocked
    old_ids = {e.entry_id for e in engine.ledger}
    new_ids = tuple(e.entry_id for e in ledger if e.entry_id not in old_ids)
    engine = replace(
        engine,
        ledger=ledger,
        session=with_approval(engine.session),
        ledger_snapshots=(
            *engine.ledger_snapshots,
            LedgerSnapshot(step=engine.step, cause="approval", ledger=ledger),
        ),
    )
    engine = _set_resolution(engine, endorsement_id, "approved", new_ids)
    return _judge(engine, call, proposal, "after_approval")


def write_ledger(
    engine: RunEngine, entry: LedgerEntry, authority: WriteAuthority
) -> tuple[RunEngine, bool]:
    """Endorsement Service stand-in: a refused write is recorded, never raised."""
    _check_open(engine)
    if engine.halted is not None:
        return engine, False
    engine = replace(engine, step=engine.step + 1)
    reason: str | None = None
    ledger = engine.ledger
    approved = {e.endorsement_id for e in engine.escalations if e.resolution == "approved"}
    if isinstance(authority, UserEndorsedAuthority) and authority.endorsement_id not in approved:
        reason = ERR_UNKNOWN_ENDORSEMENT
    else:
        try:
            ledger = with_entry(engine.ledger, entry, authority)
        except LedgerClosureError as error:
            reason = str(error)
    if reason is not None:
        refusal = RefusalRecord(step=engine.step, kind="ledger_write", reason=reason)
        return replace(engine, refusals=(*engine.refusals, refusal)), False
    if ledger != engine.ledger:
        snapshot = LedgerSnapshot(step=engine.step, cause="user_write", ledger=ledger)
        engine = replace(
            engine, ledger=ledger, ledger_snapshots=(*engine.ledger_snapshots, snapshot)
        )
    return engine, True


def update_contract(engine: RunEngine, new: IntentContract) -> tuple[RunEngine, bool]:
    """Replace the contract with a narrower or equal one; a widening is refused (I5)."""
    _check_open(engine)
    if engine.halted is not None:
        return engine, False
    engine = replace(engine, step=engine.step + 1)
    try:
        assert_monotonic(engine.contract, new)
    except ContractWideningError as error:
        refusal = RefusalRecord(
            step=engine.step, kind="contract_update", reason="; ".join(error.reasons)
        )
        return replace(engine, refusals=(*engine.refusals, refusal)), False
    if new != engine.contract:
        snapshot = ContractSnapshot(step=engine.step, cause="update", contract=new)
        engine = replace(
            engine, contract=new, contract_snapshots=(*engine.contract_snapshots, snapshot)
        )
    return engine, True


def record_so_far(engine: RunEngine) -> RunRecord:
    """The run as it stands; appends nothing."""
    return RunRecord(
        run_id=engine.run_id,
        lane=engine.lane,
        scenario=engine.scenario,
        user_request=engine.request,
        world_before=engine.world_before,
        world_after=engine.world,
        world_diff=diff(engine.world_before, engine.world),
        chain=engine.chain,
        calls=engine.calls,
        escalations=engine.escalations,
        contract_snapshots=engine.contract_snapshots,
        ledger_snapshots=engine.ledger_snapshots,
        refusals=engine.refusals,
        values=engine.store,
        session=engine.session,
        halted=engine.halted,
    )


def _run_outcome(engine: RunEngine) -> tuple[Literal["completed", "blocked", "error"], str]:
    if engine.halted is not None:
        return "error", f"halted: {engine.halted}"
    if any(r.status == "tool_error" for r in engine.calls):
        return "error", "tool error"
    last: dict[str, CallRecord] = {r.call_id: r for r in engine.calls}
    held = sum(1 for r in last.values() if r.status in ("blocked", "escalated"))
    if held:
        return "blocked", f"{held} call(s) not executed"
    return "completed", "all calls executed"


def finish(engine: RunEngine, *, oracle: OracleFn | None = None) -> tuple[RunEngine, RunRecord]:
    """Append `oracle_updated` (when an oracle is given) and `run_finished`; returns the record."""
    _check_open(engine)
    if engine.halted is None and oracle is not None:
        result = oracle(record_so_far(engine))
        engine = _emit(
            engine,
            lambda run, lane, seq: OracleUpdated(
                type="oracle_updated", run_id=run, lane=lane, seq=seq, result=result
            ),
        )
    outcome, summary = _run_outcome(engine)
    engine = _emit(
        engine,
        lambda run, lane, seq: RunFinished(
            type="run_finished",
            run_id=run,
            lane=lane,
            seq=seq,
            outcome=outcome,
            summary=summary,
        ),
    )
    engine = replace(engine, finished=True)
    return engine, record_so_far(engine)


def _approves(mode: EscalationMode, call_id: str) -> bool:
    if isinstance(mode, ScriptedApprovals):
        return call_id in mode.approve
    return mode == "approve_all"


def execute_run(
    *,
    scenario: str,
    run_id: str,
    request: str,
    world: WorldState,
    contract: IntentContract,
    ledger: Sequence[LedgerEntry],
    calls: Sequence[RawToolCall],
    session: SessionState | None = None,
    lane: Lane = "notary",
    monitor: Monitor | None = None,
    gateway: GatewayLabeler | None = None,
    resolver: ArgResolver | None = None,
    escalation: EscalationMode = "reject",
    oracle: OracleFn | None = None,
    audit_append: AuditAppend = append,
) -> RunRecord:
    """Run every call in order, resolving each escalation at once as `escalation` says."""
    engine = start_run(
        run_id=run_id,
        scenario=scenario,
        request=request,
        world=world,
        contract=contract,
        ledger=ledger,
        session=session,
        lane=lane,
        monitor=monitor,
        gateway=gateway,
        resolver=resolver,
        audit_append=audit_append,
    )
    for call in calls:
        engine, outcome = propose(engine, call)
        approvals = 0
        while outcome.status == "escalated" and outcome.endorsement_id is not None:
            approve = _approves(escalation, call.call_id) and approvals < MAX_ESCALATION_ROUNDS
            if approve:
                approvals += 1
            engine, resolved = resolve_escalation(
                engine, outcome.endorsement_id, "approve" if approve else "reject"
            )
            if resolved is None:
                break
            outcome = resolved
    return finish(engine, oracle=oracle)[1]


def run_hijacked(
    scenario: Scenario,
    commands: Sequence[HijackedToolCallCommand],
    *,
    monitor: Monitor | None = None,
    gateway: GatewayLabeler | None = None,
    resolver: ArgResolver | None = None,
    escalation: EscalationMode = "reject",
    oracle: OracleFn | None = None,
    audit_append: AuditAppend = append,
) -> RunRecord:
    """Hijacked Mode: a judge's raw tool calls run against the scenario, no LLM involved."""
    if not commands:
        raise ValueError("no commands")
    run_id = commands[0].run_id
    if any(c.run_id != run_id for c in commands):
        raise ValueError("hijacked commands must share one run_id")
    call_ids = [c.call_id for c in commands]
    if len(set(call_ids)) != len(call_ids):
        raise ValueError("hijacked call ids must be unique")
    return execute_run(
        scenario=scenario.scenario_id,
        run_id=run_id,
        request=scenario.user_request,
        world=scenario.world,
        contract=scenario.contract,
        ledger=scenario.ledger,
        session=scenario.session,
        calls=[RawToolCall(call_id=c.call_id, tool=c.tool, args=c.args) for c in commands],
        lane="notary",
        monitor=monitor,
        gateway=gateway,
        resolver=resolver,
        escalation=escalation,
        oracle=oracle,
        audit_append=audit_append,
    )
