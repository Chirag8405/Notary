"""Step 2 (irreversibility): irreversible tools need explicit authorization."""

import pytest
from builders import step_input

from notary_core.models import ToolEffect
from notary_core.policy.sensitive_params import PolicyTable, make_tool_policy
from notary_core.steps.irreversibility import check_irreversibility


def _table(tool: str, effect: ToolEffect) -> PolicyTable:
    return {tool: make_tool_policy(effect, {})}


@pytest.mark.attack("A4")
def test_irreversible_tool_without_authorization_is_blocked() -> None:
    inp = step_input(
        "delete_email", effect="irreversible", policy=_table("delete_email", "irreversible")
    )
    outcome = check_irreversibility(inp)
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "IRREVERSIBLE_NOT_AUTHORIZED")


@pytest.mark.attack("A4")
def test_irreversible_tool_with_authorization_passes() -> None:
    inp = step_input(
        "delete_email",
        effect="irreversible",
        authorized=("delete_email",),
        policy=_table("delete_email", "irreversible"),
    )
    assert check_irreversibility(inp) is None


@pytest.mark.attack("A4")
def test_write_tool_passes() -> None:
    assert (
        check_irreversibility(step_input("send_email", policy=_table("send_email", "write")))
        is None
    )


def test_read_tool_passes() -> None:
    inp = step_input("read_email", effect="read", policy=_table("read_email", "read"))
    assert check_irreversibility(inp) is None


@pytest.mark.invariant("I2")
def test_table_effect_overrides_relaxed_declaration() -> None:
    inp = step_input("delete_email", effect="read", policy=_table("delete_email", "irreversible"))
    outcome = check_irreversibility(inp)
    assert outcome is not None
    assert outcome.code == "IRREVERSIBLE_NOT_AUTHORIZED"


@pytest.mark.attack("A4")
def test_unknown_tool_is_treated_as_irreversible() -> None:
    outcome = check_irreversibility(step_input("mystery_tool", effect="read", policy={}))
    assert outcome is not None
    assert outcome.code == "IRREVERSIBLE_NOT_AUTHORIZED"


def test_tool_missing_from_contract_is_blocked_defensively() -> None:
    outcome = check_irreversibility(step_input("pay_bill", contract_tools=()))
    assert outcome is not None
    assert outcome.code == "IRREVERSIBLE_NOT_AUTHORIZED"
