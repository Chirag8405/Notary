"""Small constructors shared by the executor tests."""

from collections.abc import Iterable, Mapping, Sequence

from notary_core.audit import append
from notary_core.models import (
    CHECK_ORDER,
    AuditEntry,
    Decision,
    EffectBudget,
    Event,
    IntentContract,
    LedgerEntry,
    Reason,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
    ToolScope,
)
from notary_core.monitor import Monitor


def allow_all_monitor() -> Monitor:
    """ALLOW every call, with one passing reason per check."""

    def monitor(
        contract: IntentContract,
        proposal: ToolCallProposal,
        values: Mapping[str, ResolvedValue],
        ledger: Sequence[LedgerEntry],
        session: SessionState,
    ) -> Decision:
        reasons = tuple(
            Reason(check=c, outcome="pass", code="STEP_PASS", detail="") for c in CHECK_ORDER
        )
        return Decision(verdict="ALLOW", reasons=reasons, diff_card=None)

    return monitor


def block_all_monitor() -> Monitor:
    """BLOCK every call on scope."""

    def monitor(
        contract: IntentContract,
        proposal: ToolCallProposal,
        values: Mapping[str, ResolvedValue],
        ledger: Sequence[LedgerEntry],
        session: SessionState,
    ) -> Decision:
        reason = Reason(check="scope", outcome="fail", code="SCOPE_TOOL_NOT_IN_CONTRACT", detail="")
        return Decision(verdict="BLOCK", reasons=(reason,), diff_card=None)

    return monitor


def contract_with(tools: tuple[ToolScope, ...], max_approvals: int = 3) -> IntentContract:
    return IntentContract(
        contract_id="contract-test",
        user_intent="test",
        allowed_tools=tools,
        budget=EffectBudget(
            max_effects=10,
            max_spend_cents=20000,
            max_egress_bytes=10000,
            max_call_amount_cents=20000,
            max_approvals=max_approvals,
        ),
        egress_hosts=(),
        authorized_irreversible=tuple(t.tool for t in tools if t.effect == "irreversible"),
    )


def rebuild_chain(events: Iterable[Event]) -> tuple[AuditEntry, ...]:
    chain: tuple[AuditEntry, ...] = ()
    for event in events:
        chain = append(chain, event)
    return chain


def types_collapsed(events: Iterable[Event]) -> list[str]:
    """Event types, with runs of consecutive `value_labeled` collapsed to one."""
    out: list[str] = []
    for event in events:
        if event.type == "value_labeled" and out and out[-1] == "value_labeled":
            continue
        out.append(event.type)
    return out
