"""decide() wiring: scope lookup, read-only bypass, determinism and the steps registry."""

import copy
from collections.abc import Callable

import pytest

from notary_core.models import (
    CHECK_ORDER,
    IntentContract,
    SessionState,
    ToolCallProposal,
    ToolScope,
)
from notary_core.monitor import decide
from notary_core.policy.sensitive_params import PolicyTable, make_tool_policy
from notary_core.steps import STEPS, not_implemented_step
from notary_core.steps.budget import check_budget
from notary_core.steps.irreversibility import check_irreversibility
from notary_core.steps.origin import check_origin
from notary_core.steps.scope import check_scope


def _read_case(
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
) -> tuple[IntentContract, ToolCallProposal, SessionState, PolicyTable]:
    contract = make_contract(tools=(make_scope("read_email", effect="read"),))
    policy: PolicyTable = {"read_email": make_tool_policy("read", {})}
    return contract, make_proposal("read_email"), make_session(), policy


@pytest.mark.attack("A1")
def test_unknown_tool_is_blocked_by_scope_step(
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
) -> None:
    decision = decide(make_contract(), make_proposal("send_email"), {}, (), make_session())
    assert decision.verdict == "BLOCK"
    assert [(r.check, r.code) for r in decision.reasons] == [
        ("scope", "SCOPE_TOOL_NOT_IN_CONTRACT")
    ]


@pytest.mark.invariant("I6")
def test_read_only_tool_is_allowed_after_scope(
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
) -> None:
    contract, proposal, session, policy = _read_case(
        make_scope, make_contract, make_proposal, make_session
    )
    decision = decide(contract, proposal, {}, (), session, policy=policy)
    assert decision.verdict == "ALLOW"
    assert [(r.check, r.outcome, r.code) for r in decision.reasons] == [
        ("scope", "pass", "READ_ONLY_UNGATED")
    ]


@pytest.mark.invariant("I2")
def test_read_declaration_cannot_bypass_an_irreversible_table_entry(
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
) -> None:
    """The contract says `read` but the table says `irreversible`: no bypass, steps 2+ run."""
    contract = make_contract(tools=(make_scope("delete_email", effect="read"),))
    policy: PolicyTable = {"delete_email": make_tool_policy("irreversible", {})}
    decision = decide(
        contract, make_proposal("delete_email"), {}, (), make_session(), policy=policy
    )
    assert decision.verdict == "BLOCK"
    assert decision.reasons[-1].code == "IRREVERSIBLE_NOT_AUTHORIZED"


@pytest.mark.invariant("I6")
def test_decide_is_deterministic(
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
) -> None:
    contract, proposal, session, policy = _read_case(
        make_scope, make_contract, make_proposal, make_session
    )
    first = decide(contract, proposal, {}, (), session, policy=policy)
    second = decide(contract, proposal, {}, (), session, policy=policy)
    assert first.model_dump_json() == second.model_dump_json()


@pytest.mark.invariant("I6")
def test_decide_does_not_mutate_inputs(
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
) -> None:
    contract, proposal, session, policy = _read_case(
        make_scope, make_contract, make_proposal, make_session
    )
    snapshot = copy.deepcopy((contract, proposal, session, policy))
    decide(contract, proposal, {}, (), session, policy=policy)
    assert (contract, proposal, session, policy) == snapshot


def test_steps_registry_is_in_check_order() -> None:
    assert [name for name, _ in STEPS] == list(CHECK_ORDER)


def test_steps_registry_uses_real_steps_where_they_exist() -> None:
    registry = dict(STEPS)
    assert registry["scope"] is check_scope
    assert registry["irreversibility"] is check_irreversibility
    assert registry["origin"] is check_origin
    assert registry["budget"] is check_budget
    assert all(registry[name] is not_implemented_step for name in CHECK_ORDER[3:5])
