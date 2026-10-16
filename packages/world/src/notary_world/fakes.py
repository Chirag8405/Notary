"""Test-support doubles for the frozen contracts. Never imported by `notary_core`.

`FakeMonitor` returns each scripted call's expected verdict, so other lanes can build against
the `decide()` signature before the real monitor exists. `FakeGateway` / `FakeValueStore` do the
same for the pure Gateway and Value Store interfaces.
"""

import hashlib
from collections.abc import Iterable, Mapping, Sequence

from notary_core.gateway import ToolResult
from notary_core.models import (
    CHECK_ORDER,
    CheckName,
    Decision,
    DiffCard,
    DiffRow,
    EmailOrigin,
    ExpectedOutcome,
    FileOrigin,
    IntentContract,
    Label,
    LedgerEntry,
    Origin,
    Reason,
    ReasonCode,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
    ToolOrigin,
    ValueRef,
)
from notary_world.models import AttackFixture

DEFAULT_BLOCK_CODE: dict[CheckName, ReasonCode] = {
    "scope": "SCOPE_TOOL_NOT_IN_CONTRACT",
    "irreversibility": "IRREVERSIBLE_NOT_AUTHORIZED",
    "origin": "ORIGIN_UNTRUSTED",
    "corroboration": "LEDGER_NOT_FOUND",
    "confidentiality": "CONF_READER_VIOLATION",
    "budget": "BUDGET_AMOUNT",
}


def _pass(check: CheckName, code: ReasonCode = "STEP_PASS") -> Reason:
    return Reason(check=check, outcome="pass", code=code, detail="fake monitor")


def decision_for(expected: ExpectedOutcome, diff_card: DiffCard | None = None) -> Decision:
    """Build a valid `Decision` realizing an expected outcome."""
    if expected.verdict == "ALLOW":
        if expected.code == "READ_ONLY_UNGATED":
            return Decision(
                verdict="ALLOW", reasons=(_pass("scope", "READ_ONLY_UNGATED"),), diff_card=None
            )
        reasons = tuple(
            _pass(
                c,
                "LEDGER_EXACT_MATCH"
                if expected.code == "LEDGER_EXACT_MATCH" and c == "corroboration"
                else "STEP_PASS",
            )
            for c in CHECK_ORDER
        )
        return Decision(verdict="ALLOW", reasons=reasons, diff_card=None)
    if expected.deciding_check is None:
        raise ValueError("BLOCK and ESCALATE need a deciding_check")
    deciding = CHECK_ORDER.index(expected.deciding_check)
    before = tuple(_pass(c) for c in CHECK_ORDER[:deciding])
    if expected.verdict == "BLOCK":
        code = expected.code or DEFAULT_BLOCK_CODE[expected.deciding_check]
        fail = Reason(
            check=expected.deciding_check, outcome="fail", code=code, detail="fake monitor"
        )
        return Decision(verdict="BLOCK", reasons=(*before, fail), diff_card=None)
    escalate = Reason(
        check=expected.deciding_check,
        outcome="escalate",
        code="LEDGER_NOVEL_ESCALATE",
        detail="fake monitor",
    )
    after = tuple(_pass(c) for c in CHECK_ORDER[deciding + 1 :])
    return Decision(verdict="ESCALATE", reasons=(*before, escalate, *after), diff_card=diff_card)


class FakeMonitor:
    """Satisfies `notary_core.monitor.Monitor`; answers from the fixtures' scripted calls."""

    def __init__(self, fixtures: Sequence[AttackFixture]) -> None:
        self._expected: dict[str, ExpectedOutcome] = {
            call.call_id: call.expected for fx in fixtures for call in fx.scripted
        }

    def __call__(
        self,
        contract: IntentContract,
        proposal: ToolCallProposal,
        values: Mapping[str, ResolvedValue],
        ledger: Sequence[LedgerEntry],
        session: SessionState,
    ) -> Decision:
        expected = self._expected.get(proposal.call_id)
        if expected is None:
            return decision_for(
                ExpectedOutcome(
                    verdict="BLOCK", deciding_check="scope", code="SCOPE_TOOL_NOT_IN_CONTRACT"
                )
            )
        card = None
        if expected.verdict == "ESCALATE" and proposal.args:
            param, ref = sorted(proposal.args.items())[0]
            resolved = values.get(ref.id)
            card = DiffCard(
                rows=(
                    DiffRow(
                        param=param,
                        value_id=ref.id,
                        origin=ref.label.origin,
                        integrity=ref.label.integrity,
                        preview=resolved.text if resolved else "",
                        nearest_ledger_value=None,
                        differing_positions=(),
                    ),
                )
            )
        return decision_for(expected, card)


class FakeValueStore:
    """Immutable in-memory Value Store (satisfies `notary_core.gateway.ValueStore`)."""

    def __init__(self, values: Mapping[str, ResolvedValue] | None = None) -> None:
        self._values: dict[str, ResolvedValue] = dict(values or {})

    def get(self, value_id: str) -> ResolvedValue | None:
        return self._values.get(value_id)

    def with_values(self, values: Iterable[ResolvedValue]) -> "FakeValueStore":
        merged = dict(self._values)
        for value in values:
            merged[value.ref.id] = value
        return FakeValueStore(merged)

    def as_mapping(self) -> Mapping[str, ResolvedValue]:
        return dict(self._values)


def _origin_for(tool: str) -> Origin:
    if tool in {"read_inbox", "read_email"}:
        return EmailOrigin(kind="email")
    if tool in {"read_file", "list_files"}:
        return FileOrigin(kind="file")
    return ToolOrigin(kind="tool", name=tool)


class FakeGateway:
    """Satisfies `notary_core.gateway.GatewayLabeler`: every tool result field is untrusted."""

    def __call__(
        self, result: ToolResult, *, readers: tuple[str, ...]
    ) -> tuple[ResolvedValue, ...]:
        origin = _origin_for(result.tool)
        out: list[ResolvedValue] = []
        for field in result.fields:
            label = Label(origin=origin, integrity="untrusted", readers=readers, span_pointer=None)
            digest = hashlib.sha256(field.text.encode("utf-8")).hexdigest()
            ref = ValueRef(id=f"{result.record_id}.{field.name}", label=label, content_hash=digest)
            out.append(ResolvedValue(ref=ref, unit=field.unit, text=field.text))
        return tuple(out)
