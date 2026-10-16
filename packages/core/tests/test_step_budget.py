"""Step 6 (budget): amount caps, effect count, egress volume and approval budget."""

from collections.abc import Callable
from dataclasses import replace

import pytest

from notary_core.models import (
    EffectBudget,
    FreeMarker,
    IntentContract,
    ResolvedValue,
    SessionState,
    ToolEffect,
    ToolScope,
)
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import ParamPolicy, PolicyTable, make_tool_policy
from notary_core.steps.budget import check_budget

Make = Callable[..., StepInput]


def _policy(effect: ToolEffect = "write") -> PolicyTable:
    free = FreeMarker(kind="free")
    return {
        "pay_bill": make_tool_policy(
            effect,
            {
                "amount": ParamPolicy(unit="amount", floor=free, kind="amount"),
                "body": ParamPolicy(unit=None, floor=free, kind="payload"),
            },
        )
    }


def _budget(**overrides: int) -> EffectBudget:
    fields = {
        "max_effects": 2,
        "max_spend_cents": 20000,
        "max_egress_bytes": 1000,
        "max_call_amount_cents": 20000,
        "max_approvals": 3,
    }
    return EffectBudget(**{**fields, **overrides})


@pytest.fixture
def build(
    make_input: Make,
    make_contract: Callable[..., IntentContract],
    make_scope: Callable[..., ToolScope],
    make_session: Callable[..., SessionState],
    make_value: Callable[..., ResolvedValue],
) -> Callable[..., StepInput]:
    def factory(
        amount: str | None = None,
        body: str | None = None,
        *,
        effect: ToolEffect = "write",
        budget: EffectBudget | None = None,
        prior_escalated: bool = False,
        **session: int,
    ) -> StepInput:
        args: dict[str, ResolvedValue] = {}
        if amount is not None:
            args["amount"] = make_value("v-amount", amount, unit="amount")
        if body is not None:
            args["body"] = make_value("v-body", body)
        contract = make_contract(
            tools=(make_scope("pay_bill", effect=effect),), budget=budget or _budget()
        )
        return make_input(
            "pay_bill",
            effect=effect,
            args=args,
            contract=contract,
            session=make_session(**session),
            policy=_policy(effect),
            prior_escalated=prior_escalated,
        )

    return factory


@pytest.mark.attack("A11")
def test_amount_over_per_call_cap_is_blocked(build: Make) -> None:
    outcome = check_budget(build("250.00"))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "BUDGET_AMOUNT")


@pytest.mark.attack("A11")
def test_cumulative_spend_cap_is_blocked(build: Make) -> None:
    outcome = check_budget(build("50.00", spent_cents=18000))
    assert outcome is not None
    assert outcome.code == "BUDGET_AMOUNT"


@pytest.mark.attack("A14")
def test_amount_within_budget_passes(build: Make) -> None:
    assert check_budget(build("120.00")) is None


@pytest.mark.attack("A9")
def test_unparseable_amount_fails_closed(build: Make) -> None:
    for text in ("twelve", "12.345", "-5", ""):
        outcome = check_budget(build(text))
        assert outcome is not None
        assert outcome.code == "BUDGET_AMOUNT"
        assert outcome.detail == "amount could not be parsed exactly"


def test_amount_cap_is_exact_to_the_cent(build: Make) -> None:
    assert check_budget(build("200.00")) is None
    assert check_budget(build("200.01")) is not None


@pytest.mark.attack("A9")
def test_unresolved_amount_fails_closed(build: Make) -> None:
    inp = build("10.00")
    outcome = check_budget(replace(inp, values={}))
    assert outcome is not None
    assert outcome.code == "BUDGET_AMOUNT"


@pytest.mark.attack("A12")
def test_effect_count_cap(build: Make) -> None:
    outcome = check_budget(build(effects_used=2))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "BUDGET_SENDS")
    assert check_budget(build(effects_used=1)) is None


@pytest.mark.attack("A14")
def test_read_tool_does_not_consume_effect_budget(build: Make) -> None:
    assert check_budget(build(effect="read", effects_used=2)) is None


@pytest.mark.attack("A12")
def test_egress_bytes_cap(build: Make) -> None:
    outcome = check_budget(build(body="x" * 1001))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "BUDGET_EGRESS_BYTES")
    assert check_budget(build(body="x" * 1000)) is None
    assert check_budget(build(body="x" * 10, egress_bytes_used=995)) is not None


@pytest.mark.attack("A12")
def test_egress_counts_utf8_bytes_not_characters(build: Make) -> None:
    assert check_budget(build(body="é" * 501)) is not None


@pytest.mark.attack("A11")
def test_escalation_becomes_block_when_approvals_exhausted(build: Make) -> None:
    outcome = check_budget(build(prior_escalated=True, approvals_used=3))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "BUDGET_APPROVALS_EXHAUSTED")


@pytest.mark.attack("A11")
def test_escalation_allowed_while_approvals_remain(build: Make) -> None:
    assert check_budget(build(prior_escalated=True, approvals_used=2)) is None


@pytest.mark.attack("A11")
def test_no_escalation_no_approval_check(build: Make) -> None:
    assert check_budget(build(prior_escalated=False, approvals_used=3)) is None


@pytest.mark.attack("A12")
def test_block_responses_are_uniform(build: Make) -> None:
    first = check_budget(build(body="A" * 2000))
    second = check_budget(build(body="S3CR3T" * 400))
    assert first is not None
    assert first == second
    assert "S3CR3T" not in first.detail


def test_first_failing_check_wins(build: Make) -> None:
    inp = build("250.00", body="x" * 2000, effects_used=2)
    outcome = check_budget(inp)
    assert outcome is not None
    assert outcome.code == "BUDGET_AMOUNT"
