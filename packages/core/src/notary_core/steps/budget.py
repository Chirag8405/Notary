"""Step 6: the call fits the remaining effect budget, and approvals have not run out."""

from notary_core.models import ResolvedValue
from notary_core.models.decision import ReasonCode, StepOutcome
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import effective_effect, param_policy
from notary_core.units import canonicalize_amount, to_cents

MAX_ESCALATIONS_PER_APPROVAL: int = 3
"""Cards the monitor may raise per approval in the budget. With `max_approvals` = 3 that is 9
cards; the 10th escalation is a BLOCK. Rejected cards count too, which is what bounds a flood."""


def _block(code: ReasonCode, detail: str) -> StepOutcome:
    return StepOutcome(verdict="BLOCK", code=code, detail=detail, diff_card=None)


def _arguments(inp: StepInput, kind: str) -> list[ResolvedValue | None]:
    """The resolved value of every argument whose table kind is `kind` (None = not resolvable)."""
    return [
        inp.values.get(ref.id)
        for name, ref in inp.proposal.args.items()
        if param_policy(inp.policy, inp.proposal.tool, name).kind == kind
    ]


def check_budget(inp: StepInput) -> StepOutcome | None:
    """BLOCK when an amount, effect count or egress volume exceeds the budget.

    Also turns an earlier ESCALATE into a BLOCK once the approval budget is exhausted, or once the
    cards already raised (approved or not) reach `MAX_ESCALATIONS_PER_APPROVAL` per approval, so
    a flood of cards cannot go on for ever (A11). Anything
    that cannot be measured exactly fails closed. Details are constant strings (A12).
    """
    budget = inp.contract.budget
    session = inp.session
    declared = None if inp.scope is None else inp.scope.effect
    effect = effective_effect(inp.policy, inp.proposal.tool, declared)

    total_cents = 0
    for value in _arguments(inp, "amount"):
        cents = None if value is None else to_cents(canonicalize_amount(value.text))
        if cents is None:
            return _block("BUDGET_AMOUNT", "amount could not be parsed exactly")
        total_cents += cents
    if (
        total_cents > budget.max_call_amount_cents
        or session.spent_cents + total_cents > budget.max_spend_cents
    ):
        return _block("BUDGET_AMOUNT", "amount exceeds the budget")

    if effect != "read" and session.effects_used + 1 > budget.max_effects:
        return _block("BUDGET_SENDS", "effect count exceeds the budget")

    payload_bytes = 0
    for value in _arguments(inp, "payload"):
        if value is None:
            return _block("BUDGET_EGRESS_BYTES", "egress volume exceeds the budget")
        payload_bytes += len(value.text.encode("utf-8"))
    if session.egress_bytes_used + payload_bytes > budget.max_egress_bytes:
        return _block("BUDGET_EGRESS_BYTES", "egress volume exceeds the budget")

    if inp.prior_escalated and session.approvals_used >= budget.max_approvals:
        return _block("BUDGET_APPROVALS_EXHAUSTED", "approval budget is exhausted")
    if (
        inp.prior_escalated
        and session.escalations_used >= budget.max_approvals * MAX_ESCALATIONS_PER_APPROVAL
    ):
        return _block("BUDGET_ESCALATIONS_EXHAUSTED", "escalation budget is exhausted")
    return None
