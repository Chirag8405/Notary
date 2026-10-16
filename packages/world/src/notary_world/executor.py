"""Run executor and Hijacked Mode runner: raw tool calls through the monitor, no LLM involved.

Each call goes label -> monitor -> write-ahead audit entry -> world tool (only on ALLOW) -> label
the result. The `RunRecord` it returns is what the oracle, the fuzz harness, the CLI and the attack
fixtures consume. Every operation is a pure function of an immutable `RunEngine`.
"""

from collections.abc import Callable, Mapping, Sequence
from typing import Literal, Protocol

from notary_core.canon import sha256_hex
from notary_core.models import (
    AuditEntry,
    Decision,
    DecisionUnit,
    Event,
    IntentContract,
    Label,
    Lane,
    LedgerEntry,
    LlmOrigin,
    NotaryModel,
    OracleResult,
    ResolvedValue,
    SessionState,
    SpanPointer,
    ToolCallProposal,
    ValueRef,
)
from notary_core.provenance import INTEGRITY_ORDER, join_all_readers, normalize_readers
from notary_core.units import canonicalize
from notary_world.state import WorldDiff, WorldState
from notary_world.tools import (
    EffectRecord,
)

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
