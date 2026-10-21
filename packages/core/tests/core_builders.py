"""Small constructors for valid contract objects, shared by the contract tests."""

import hashlib

from notary_core.models import (
    CheckName,
    Decision,
    EffectBudget,
    FreeMarker,
    IntentContract,
    Label,
    Reason,
    ReasonCode,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
    ToolScope,
    UserOrigin,
    ValueRef,
)
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import DEFAULT_POLICY, PolicyTable


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def budget() -> EffectBudget:
    return EffectBudget(
        max_effects=2,
        max_spend_cents=20000,
        max_egress_bytes=1000,
        max_call_amount_cents=20000,
        max_approvals=3,
    )


def scope(tool: str, effect: str = "write") -> ToolScope:
    return ToolScope.model_validate(
        {
            "tool": tool,
            "params": {"amount": FreeMarker(kind="free")},
            "manifest_hash": sha(tool),
            "effect": effect,
        }
    )


def contract(
    tools: tuple[ToolScope, ...] = (),
    egress: tuple[str, ...] = (),
    authorized: tuple[str, ...] = (),
) -> IntentContract:
    return IntentContract(
        contract_id="c1",
        user_intent="pay the bill",
        allowed_tools=tools,
        budget=budget(),
        egress_hosts=egress,
        authorized_irreversible=authorized,
    )


def reason(check: CheckName, outcome: str, code: ReasonCode) -> Reason:
    return Reason.model_validate({"check": check, "outcome": outcome, "code": code, "detail": ""})


def decision(verdict: str, *reasons: Reason) -> Decision:
    return Decision.model_validate({"verdict": verdict, "reasons": reasons, "diff_card": None})


def value_ref(value_id: str, text: str = "x") -> ValueRef:
    label = Label(
        origin=UserOrigin(kind="user"), integrity="trusted", readers=(), span_pointer=None
    )
    return ValueRef(id=value_id, label=label, content_hash=sha(text))


def step_input(
    tool: str = "pay_bill",
    *,
    effect: str = "write",
    contract_tools: tuple[ToolScope, ...] | None = None,
    authorized: tuple[str, ...] = (),
    args: dict[str, ValueRef] | None = None,
    manifest_hash: str | None = None,
    policy: PolicyTable = DEFAULT_POLICY,
    values: dict[str, ResolvedValue] | None = None,
) -> StepInput:
    """A `StepInput` for `tool`, whose scope is looked up in `contract_tools` (default: itself)."""
    tool_scope = scope(tool, effect)
    tools = (tool_scope,) if contract_tools is None else contract_tools
    return StepInput(
        contract=contract(tools, authorized=authorized),
        proposal=ToolCallProposal(
            call_id="call-1",
            tool=tool,
            manifest_hash=manifest_hash or sha(tool),
            args={} if args is None else args,
        ),
        values={} if values is None else values,
        ledger=(),
        session=SessionState(
            spent_cents=0, effects_used=0, egress_bytes_used=0, approvals_used=0, escalations_used=0
        ),
        scope=next((t for t in tools if t.tool == tool), None),
        policy=policy,
        prior_escalated=False,
    )
