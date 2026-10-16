"""Small constructors for valid contract objects, shared by the contract tests."""

import hashlib

from notary_core.models import (
    CheckName,
    Decision,
    EffectBudget,
    FreeMarker,
    IntentContract,
    Reason,
    ReasonCode,
    ToolScope,
)


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
