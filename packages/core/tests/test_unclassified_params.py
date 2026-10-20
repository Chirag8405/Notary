"""Unclassified parameters fail closed at the monitor (#298).

A parameter that the sensitive-parameter table does not list falls back to `UNKNOWN_PARAM`
(endorse floor), so a contract marker can never make it looser than `endorse`: an untrusted-origin
value is never ALLOWed, and a trusted user-typed value may pass (that is what `endorse` means).
A `read` tool stays ungated by design (decisions.md, "Read tools with text parameters").
"""

from collections.abc import Callable
from typing import NamedTuple

import pytest

from notary_core.models import (
    EndorseMarker,
    FreeMarker,
    Integrity,
    IntentContract,
    LedgerMarker,
    LiteralMarker,
    Marker,
    NamedSourceMarker,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
    ToolEffect,
    ToolScope,
)
from notary_core.monitor import decide
from notary_core.policy.sensitive_params import DEFAULT_POLICY, UNKNOWN_PARAM, param_policy

# (tool, effect, unclassified param). `send_email` is a table `write` tool, `pay_bill` a table
# `irreversible` tool and `wire_funds` is absent from the table (an unknown tool is irreversible).
TOOLS: list[tuple[str, ToolEffect, str]] = [
    ("send_email", "write", "bcc"),
    ("pay_bill", "irreversible", "memo"),
    ("wire_funds", "irreversible", "note"),
]
TOOL_IDS = [tool for tool, _, _ in TOOLS]

FREE = FreeMarker(kind="free")
ENDORSE = EndorseMarker(kind="endorse")

# (id, marker, verdict for a trusted user value, verdict for an untrusted email value)
CASES: list[tuple[str, Marker, str, str]] = [
    ("free", FREE, "ALLOW", "ESCALATE"),
    ("endorse", ENDORSE, "ALLOW", "ESCALATE"),
    ("ledger", LedgerMarker(kind="ledger", ledger="contacts"), "ALLOW", "BLOCK"),
    ("named_source_user", NamedSourceMarker(kind="named_source", source="user"), "ALLOW", "BLOCK"),
    (
        "named_source_email",
        NamedSourceMarker(kind="named_source", source="email"),
        "BLOCK",
        "BLOCK",
    ),
    ("literal_other", LiteralMarker(kind="literal", value="x@y.example"), "BLOCK", "BLOCK"),
]
CASE_IDS = [case[0] for case in CASES]


class _Env(NamedTuple):
    make_scope: Callable[..., ToolScope]
    make_contract: Callable[..., IntentContract]
    make_proposal: Callable[..., ToolCallProposal]
    make_session: Callable[..., SessionState]


def _run(
    tool: str,
    effect: ToolEffect,
    param: str,
    marker: Marker,
    value: ResolvedValue,
    *,
    env: "_Env",
    authorize: bool = True,
) -> tuple[str, list[str]]:
    contract = env.make_contract(
        tools=(env.make_scope(tool, effect=effect, params={param: marker}),),
        authorized_irreversible=(tool,) if authorize and effect == "irreversible" else (),
    )
    decision = decide(
        contract,
        env.make_proposal(tool, **{param: value}),
        {value.ref.id: value},
        (),
        env.make_session(),
    )
    return decision.verdict, [r.code for r in decision.reasons]


def test_the_params_under_test_are_really_unclassified() -> None:
    for tool, _, param in TOOLS:
        assert param_policy(DEFAULT_POLICY, tool, param) is UNKNOWN_PARAM
    assert UNKNOWN_PARAM.floor.kind == "endorse"


@pytest.mark.invariant("I2")
@pytest.mark.parametrize(("tool", "effect", "param"), TOOLS, ids=TOOL_IDS)
@pytest.mark.parametrize(
    ("marker", "trusted_verdict", "untrusted_verdict"), [c[1:] for c in CASES], ids=CASE_IDS
)
def test_unclassified_param_is_no_looser_than_the_endorse_floor(
    tool: str,
    effect: ToolEffect,
    param: str,
    marker: Marker,
    trusted_verdict: str,
    untrusted_verdict: str,
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
    make_value: Callable[..., ResolvedValue],
) -> None:
    env = _Env(make_scope, make_contract, make_proposal, make_session)
    trusted = make_value("v1", "a@b.example", unit="email")
    untrusted = make_value(
        "v2", "evil@x.example", unit="email", origin="email", integrity="untrusted"
    )
    assert _run(tool, effect, param, marker, trusted, env=env)[0] == trusted_verdict
    verdict, _ = _run(tool, effect, param, marker, untrusted, env=env)
    assert verdict == untrusted_verdict
    assert verdict != "ALLOW"


@pytest.mark.invariant("I2")
@pytest.mark.parametrize(("tool", "effect", "param"), TOOLS, ids=TOOL_IDS)
@pytest.mark.parametrize("integrity", ["untrusted", "endorsed"])
@pytest.mark.parametrize("origin", ["email", "file", "web", "llm", "tool:search"])
def test_non_trusted_value_under_free_marker_is_escalated(
    tool: str,
    effect: ToolEffect,
    param: str,
    integrity: Integrity,
    origin: str,
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
    make_value: Callable[..., ResolvedValue],
) -> None:
    value = make_value("v1", "evil@x.example", unit="email", origin=origin, integrity=integrity)
    verdict, codes = _run(
        tool,
        effect,
        param,
        FREE,
        value,
        env=_Env(make_scope, make_contract, make_proposal, make_session),
    )
    assert verdict == "ESCALATE"
    assert "LEDGER_NOVEL_ESCALATE" in codes


@pytest.mark.invariant("I2")
def test_classified_free_text_param_is_looser_than_an_unclassified_one(
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
    make_value: Callable[..., ResolvedValue],
) -> None:
    """Contrast: the table deliberately frees `body` (payload) but not an unlisted `bcc`."""
    env = _Env(make_scope, make_contract, make_proposal, make_session)
    value = make_value("v1", "hello", origin="email", integrity="untrusted")
    assert _run("send_email", "write", "body", FREE, value, env=env)[0] == "ALLOW"
    assert _run("send_email", "write", "bcc", FREE, value, env=env)[0] == "ESCALATE"


@pytest.mark.attack("A1")
@pytest.mark.invariant("I2")
@pytest.mark.parametrize(("tool", "effect", "param"), TOOLS, ids=TOOL_IDS)
@pytest.mark.parametrize(("origin", "integrity"), [("user", "trusted"), ("email", "untrusted")])
def test_param_in_proposal_but_not_in_contract_is_blocked_by_scope(
    tool: str,
    effect: ToolEffect,
    param: str,
    origin: str,
    integrity: Integrity,
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
    make_value: Callable[..., ResolvedValue],
) -> None:
    value = make_value("v1", "a@b.example", unit="email", origin=origin, integrity=integrity)
    contract = make_contract(
        tools=(make_scope(tool, effect=effect, params={"amount": FREE}),),
        authorized_irreversible=(tool,) if effect == "irreversible" else (),
    )
    decision = decide(
        contract, make_proposal(tool, **{param: value}), {"v1": value}, (), make_session()
    )
    assert decision.verdict == "BLOCK"
    assert [(r.check, r.code) for r in decision.reasons] == [
        ("scope", "SCOPE_PARAM_NOT_IN_CONTRACT")
    ]


@pytest.mark.invariant("I1")
@pytest.mark.parametrize(("tool", "effect", "param"), TOOLS[1:], ids=TOOL_IDS[1:])
def test_unauthorized_irreversible_tool_is_blocked_whatever_the_param(
    tool: str,
    effect: ToolEffect,
    param: str,
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
    make_value: Callable[..., ResolvedValue],
) -> None:
    value = make_value("v1", "a@b.example", unit="email")
    verdict, codes = _run(
        tool,
        effect,
        param,
        FREE,
        value,
        env=_Env(make_scope, make_contract, make_proposal, make_session),
        authorize=False,
    )
    assert verdict == "BLOCK"
    assert codes[-1] == "IRREVERSIBLE_NOT_AUTHORIZED"


@pytest.mark.invariant("I5")
def test_contract_cannot_declare_an_irreversible_table_tool_as_write(
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
    make_value: Callable[..., ResolvedValue],
) -> None:
    value = make_value("v1", "hello")
    verdict, codes = _run(
        "pay_bill",
        "write",
        "memo",
        FREE,
        value,
        env=_Env(make_scope, make_contract, make_proposal, make_session),
        authorize=False,
    )
    assert verdict == "BLOCK"
    assert codes[-1] == "IRREVERSIBLE_NOT_AUTHORIZED"
