"""Policy machinery (#52): floors cannot be relaxed, unknown tools and params fail closed."""

from collections.abc import Callable

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from notary_core.models import (
    Decision,
    DecisionUnit,
    EndorseMarker,
    FreeMarker,
    IntentContract,
    LedgerEntry,
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
from notary_core.policy.sensitive_params import (
    DEFAULT_POLICY,
    EFFECT_STRICTNESS,
    UNKNOWN_PARAM,
    ManifestInfo,
    ParamBinding,
    ParamPolicy,
    PolicyCoverageError,
    PolicyTable,
    ToolPolicy,
    assert_covered,
    effective_effect,
    effective_marker,
    make_tool_policy,
    marker_rank,
    merge_with_compiler_markers,
    param_policy,
    render_markdown,
    stricter_effect,
    unclassified_params,
)

markers: st.SearchStrategy[Marker] = st.one_of(
    st.builds(LiteralMarker, kind=st.just("literal"), value=st.one_of(st.text(), st.integers())),
    st.builds(NamedSourceMarker, kind=st.just("named_source"), source=st.text()),
    st.builds(LedgerMarker, kind=st.just("ledger"), ledger=st.text()),
    st.builds(EndorseMarker, kind=st.just("endorse")),
    st.builds(FreeMarker, kind=st.just("free")),
)
effects: st.SearchStrategy[ToolEffect] = st.sampled_from(EFFECT_STRICTNESS)


def _table(effect: ToolEffect, floor: Marker) -> PolicyTable:
    param = ParamPolicy(unit="iban", floor=floor, kind="destination")
    return {"pay": make_tool_policy(effect, {"to": param})}


@pytest.mark.invariant("I2")
def test_compiler_cannot_relax_floor() -> None:
    floor = LedgerMarker(kind="ledger", ledger="vendors")
    assert merge_with_compiler_markers(floor, FreeMarker(kind="free")) == floor


@pytest.mark.invariant("I2")
def test_compiler_can_tighten_floor() -> None:
    proposed = LedgerMarker(kind="ledger", ledger="vendors")
    assert merge_with_compiler_markers(EndorseMarker(kind="endorse"), proposed) == proposed


@pytest.mark.invariant("I2")
def test_equal_rank_keeps_proposed_marker() -> None:
    proposed = NamedSourceMarker(kind="named_source", source="contacts")
    floor = NamedSourceMarker(kind="named_source", source="other")
    assert merge_with_compiler_markers(floor, proposed) == proposed


@pytest.mark.invariant("I2")
def test_equal_rank_ledger_keeps_floor() -> None:
    floor = LedgerMarker(kind="ledger", ledger="a")
    assert merge_with_compiler_markers(floor, LedgerMarker(kind="ledger", ledger="b")) == floor


@pytest.mark.invariant("I2")
def test_none_proposed_returns_floor() -> None:
    floor = EndorseMarker(kind="endorse")
    assert merge_with_compiler_markers(floor, None) == floor


@pytest.mark.invariant("I2")
@given(floor=markers, proposed=st.none() | markers)
def test_merge_never_returns_looser_than_floor(floor: Marker, proposed: Marker | None) -> None:
    assert marker_rank(merge_with_compiler_markers(floor, proposed)) <= marker_rank(floor)


@given(floor=markers, proposed=markers)
def test_merge_is_deterministic_and_pure(floor: Marker, proposed: Marker) -> None:
    first = merge_with_compiler_markers(floor, proposed)
    assert merge_with_compiler_markers(floor, proposed) == first
    assert first in (floor, proposed)


@pytest.mark.invariant("I2")
def test_unknown_tool_defaults_to_irreversible() -> None:
    assert effective_effect({}, "x", None) == "irreversible"


@pytest.mark.invariant("I2")
def test_declared_effect_cannot_be_relaxed_below_table() -> None:
    table = _table("irreversible", EndorseMarker(kind="endorse"))
    assert effective_effect(table, "pay", "read") == "irreversible"


def test_declared_effect_can_tighten_table() -> None:
    table = _table("read", EndorseMarker(kind="endorse"))
    assert effective_effect(table, "pay", "write") == "write"


def test_unknown_tool_cannot_be_relaxed_by_declared_effect() -> None:
    assert effective_effect({}, "x", "read") == "irreversible"


@given(a=effects, b=effects)
def test_stricter_effect_is_commutative_and_no_looser(a: ToolEffect, b: ToolEffect) -> None:
    result = stricter_effect(a, b)
    assert result == stricter_effect(b, a)
    assert EFFECT_STRICTNESS.index(result) <= min(
        EFFECT_STRICTNESS.index(a), EFFECT_STRICTNESS.index(b)
    )


@pytest.mark.invariant("I2")
def test_unknown_param_floor_is_endorse() -> None:
    assert param_policy({}, "t", "p") == UNKNOWN_PARAM
    assert UNKNOWN_PARAM.floor.kind == "endorse"
    assert UNKNOWN_PARAM.unit == "identifier"
    assert UNKNOWN_PARAM.kind == "other"


def test_unknown_param_of_known_tool_is_unknown_param() -> None:
    table = _table("write", LedgerMarker(kind="ledger", ledger="vendors"))
    assert param_policy(table, "pay", "memo") == UNKNOWN_PARAM


def test_known_param_returns_table_policy() -> None:
    floor = LedgerMarker(kind="ledger", ledger="vendors")
    assert param_policy(_table("write", floor), "pay", "to").floor == floor


@pytest.mark.invariant("I2")
def test_effective_marker_applies_table_floor() -> None:
    floor = LedgerMarker(kind="ledger", ledger="vendors")
    table = _table("write", floor)
    assert effective_marker(table, "pay", "to", FreeMarker(kind="free")) == floor
    assert effective_marker({}, "t", "p", FreeMarker(kind="free")) == EndorseMarker(kind="endorse")


def test_default_policy_is_read_only() -> None:
    with pytest.raises(TypeError):
        DEFAULT_POLICY["x"] = make_tool_policy("read", {})  # type: ignore[index]


def test_literal_floor_rejected() -> None:
    with pytest.raises(ValidationError):
        ParamPolicy(unit=None, floor=LiteralMarker(kind="literal", value="x"), kind="other")


@pytest.mark.invariant("I2")
def test_empty_ledger_floor_rejected() -> None:
    with pytest.raises(ValidationError):
        ParamPolicy(unit=None, floor=LedgerMarker(kind="ledger", ledger=""), kind="other")


def _param(unit: DecisionUnit | None = "iban") -> ParamPolicy:
    return ParamPolicy(unit=unit, floor=EndorseMarker(kind="endorse"), kind="destination")


def test_toolpolicy_duplicate_param_names_rejected() -> None:
    binding = ParamBinding(name="to", policy=_param())
    with pytest.raises(ValidationError):
        ToolPolicy(effect="write", params=(binding, binding))


def test_make_tool_policy_is_order_independent() -> None:
    a = make_tool_policy("write", {"to": _param(), "cc": _param("email")})
    b = make_tool_policy("write", {"cc": _param("email"), "to": _param()})
    assert a.model_dump_json() == b.model_dump_json()
    assert [binding.name for binding in a.params] == ["cc", "to"]


@pytest.mark.invariant("I2")
def test_toolpolicy_params_immutable() -> None:
    tool = make_tool_policy("write", {"to": _param()})
    with pytest.raises(ValidationError):
        tool.params = ()
    with pytest.raises(ValidationError):
        tool.params[0].name = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        tool.params[0] = tool.params[0]  # type: ignore[index]


def _manifests_for(table: PolicyTable) -> list[ManifestInfo]:
    return [
        ManifestInfo(
            tool=name,
            effect=tool.effect,
            params=tuple(binding.name for binding in tool.params),
        )
        for name, tool in table.items()
    ]


@pytest.mark.invariant("I2")
def test_default_policy_marks_payee_as_endorse_floor() -> None:
    floor = param_policy(DEFAULT_POLICY, "send_money", "payee").floor
    assert floor == EndorseMarker(kind="endorse")
    assert param_policy(DEFAULT_POLICY, "pay_bill", "payee") == param_policy(
        DEFAULT_POLICY, "send_money", "payee"
    )


PAYEE_LEDGER = LedgerMarker(kind="ledger", ledger="payees")
PAYEE_ENDORSE = EndorseMarker(kind="endorse")
ACME = "DE00ACME00000000000001"
ACME_LOOKALIKE = "DE00ACME00000000000002"
STRANGER = "DE00OTHER0000000000009"


def _pay_decision(
    payee: str,
    marker: Marker,
    make_value: Callable[..., ResolvedValue],
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_ledger_entry: Callable[..., LedgerEntry],
    make_session: Callable[..., SessionState],
) -> Decision:
    """`decide` with the default table on a `pay_bill` whose payee came from an untrusted email."""
    payee_value = make_value("v-payee", payee, unit="iban", origin="email", integrity="untrusted")
    amount = make_value("v-amount", "120.00", unit="amount")
    known = make_value("v-known", ACME, unit="iban", origin="ledger", integrity="trusted")
    scope = make_scope(
        "pay_bill",
        effect="irreversible",
        params={"payee": marker, "amount": FreeMarker(kind="free")},
    )
    return decide(
        make_contract(tools=(scope,), authorized_irreversible=("pay_bill",)),
        make_proposal("pay_bill", payee=payee_value, amount=amount),
        {payee_value.ref.id: payee_value, amount.ref.id: amount},
        (make_ledger_entry(known, "iban", ACME),),
        make_session(),
    )


@pytest.mark.attack("A3")
@pytest.mark.invariant("I2")
def test_payee_floor_lets_the_contract_endorse_but_not_relax_further() -> None:
    assert effective_marker(DEFAULT_POLICY, "pay_bill", "payee", PAYEE_ENDORSE) == PAYEE_ENDORSE
    assert effective_marker(DEFAULT_POLICY, "send_money", "payee", PAYEE_LEDGER) == PAYEE_LEDGER
    assert effective_marker(DEFAULT_POLICY, "pay_bill", "payee", FreeMarker(kind="free")) == (
        PAYEE_ENDORSE
    )
    assert effective_marker(DEFAULT_POLICY, "pay_bill", "payee", None) == PAYEE_ENDORSE


@pytest.mark.attack("A3")
@pytest.mark.invariant("I2")
def test_novel_payee_escalates_under_an_endorse_marker(
    make_value: Callable[..., ResolvedValue],
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_ledger_entry: Callable[..., LedgerEntry],
    make_session: Callable[..., SessionState],
) -> None:
    args = (make_value, make_scope, make_contract, make_proposal, make_ledger_entry, make_session)
    novel = _pay_decision(STRANGER, PAYEE_ENDORSE, *args)
    assert novel.verdict == "ESCALATE"
    assert novel.diff_card is not None
    assert [(r.check, r.code) for r in novel.reasons if r.outcome == "escalate"] == [
        ("corroboration", "LEDGER_NOVEL_ESCALATE")
    ]
    known = _pay_decision(ACME, PAYEE_ENDORSE, *args)
    assert known.verdict == "ALLOW"
    assert any(r.code == "LEDGER_EXACT_MATCH" for r in known.reasons)


@pytest.mark.attack("A8")
@pytest.mark.invariant("I2")
def test_lookalike_payee_is_still_blocked_under_an_endorse_marker(
    make_value: Callable[..., ResolvedValue],
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_ledger_entry: Callable[..., LedgerEntry],
    make_session: Callable[..., SessionState],
) -> None:
    args = (make_value, make_scope, make_contract, make_proposal, make_ledger_entry, make_session)
    decision = _pay_decision(ACME_LOOKALIKE, PAYEE_ENDORSE, *args)
    assert decision.verdict == "BLOCK"
    assert (decision.reasons[-1].check, decision.reasons[-1].code) == (
        "corroboration",
        "LEDGER_LOOKALIKE",
    )


@pytest.mark.attack("A3")
@pytest.mark.invariant("I2")
def test_a_ledger_marker_still_blocks_a_novel_payee(
    make_value: Callable[..., ResolvedValue],
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_ledger_entry: Callable[..., LedgerEntry],
    make_session: Callable[..., SessionState],
) -> None:
    args = (make_value, make_scope, make_contract, make_proposal, make_ledger_entry, make_session)
    decision = _pay_decision(STRANGER, PAYEE_LEDGER, *args)
    assert decision.verdict == "BLOCK"
    assert decision.reasons[-1].code == "LEDGER_NOT_FOUND"


@pytest.mark.invariant("I2")
def test_default_policy_effects() -> None:
    assert DEFAULT_POLICY["delete_email"].effect == "irreversible"
    assert DEFAULT_POLICY["send_money"].effect == "irreversible"
    assert DEFAULT_POLICY["pay_bill"].effect == "irreversible"
    assert DEFAULT_POLICY["read_email"].effect == "read"


@pytest.mark.invariant("I2")
def test_default_policy_destinations_name_their_ledger() -> None:
    expected = {
        ("send_email", "to"): "contacts",
        ("send_email", "cc"): "contacts",
        ("post_slack", "channel"): "channels",
        ("create_event", "attendees"): "contacts",
    }
    for (tool, param), ledger in expected.items():
        assert param_policy(DEFAULT_POLICY, tool, param).floor == LedgerMarker(
            kind="ledger", ledger=ledger
        )


@pytest.mark.invariant("I2")
def test_assert_covered_passes_for_known_manifests() -> None:
    manifests = _manifests_for(DEFAULT_POLICY)
    assert {m.tool for m in manifests} == set(DEFAULT_POLICY)
    assert_covered(DEFAULT_POLICY, manifests)


@pytest.mark.invariant("I2")
def test_assert_covered_fails_on_new_param() -> None:
    manifest = ManifestInfo(
        tool="send_money", effect="irreversible", params=("payee", "amount", "reference", "memo")
    )
    with pytest.raises(PolicyCoverageError) as error:
        assert_covered(DEFAULT_POLICY, [manifest])
    assert error.value.missing == (("send_money", "memo"),)


@pytest.mark.invariant("I2")
def test_assert_covered_fails_on_unknown_effect_tool() -> None:
    write = ManifestInfo(tool="mystery", effect="write", params=("b", "a"))
    with pytest.raises(PolicyCoverageError) as error:
        assert_covered(DEFAULT_POLICY, [write])
    assert error.value.missing == (("mystery", "a"), ("mystery", "b"))
    # an unknown tool is irreversible whatever its manifest claims
    read = ManifestInfo(tool="mystery", effect="read", params=("a",))
    with pytest.raises(PolicyCoverageError):
        assert_covered(DEFAULT_POLICY, [read])


@pytest.mark.invariant("I2")
def test_assert_covered_skips_read_tools_and_uses_stricter_effect() -> None:
    read = ManifestInfo(tool="read_email", effect="read", params=("message_id", "folder"))
    assert unclassified_params(DEFAULT_POLICY, [read]) == ()
    # the manifest may only tighten the table: a "write" read_email must classify `folder`
    tightened = ManifestInfo(tool="read_email", effect="write", params=("message_id", "folder"))
    assert unclassified_params(DEFAULT_POLICY, [tightened]) == (("read_email", "folder"),)


@pytest.mark.invariant("I2")
def test_unclassified_params_is_sorted_and_deduplicated() -> None:
    manifests = [
        ManifestInfo(tool="b_tool", effect="write", params=("z", "a")),
        ManifestInfo(tool="a_tool", effect="write", params=("x",)),
        ManifestInfo(tool="a_tool", effect="write", params=("x",)),
    ]
    assert unclassified_params({}, manifests) == (("a_tool", "x"), ("b_tool", "a"), ("b_tool", "z"))


def test_render_markdown_is_deterministic_and_sorted() -> None:
    first = render_markdown(DEFAULT_POLICY)
    assert render_markdown(DEFAULT_POLICY) == first
    assert first.endswith("\n")
    lines = first.splitlines()
    assert lines[0] == "| Tool | Effect | Param | Unit | Floor | Kind |"
    rows = [tuple(cell.strip() for cell in line.strip("|").split("|")) for line in lines[2:]]
    assert rows == sorted(rows, key=lambda row: (row[0], row[2]))
    assert len(rows) == sum(len(tool.params) for tool in DEFAULT_POLICY.values())
    assert ("send_money", "irreversible", "payee", "iban", "endorse", "destination") in rows
    assert ("send_email", "write", "body", "None", "free", "payload") in rows


def test_render_markdown_ignores_insertion_order() -> None:
    forward = dict(DEFAULT_POLICY)
    backward = dict(reversed(list(DEFAULT_POLICY.items())))
    assert render_markdown(forward) == render_markdown(backward)


@pytest.mark.invariant("I3")
def test_every_destination_param_has_a_unit_or_is_identifier() -> None:
    for tool in DEFAULT_POLICY.values():
        for binding in tool.params:
            if binding.policy.kind == "destination":
                assert binding.policy.unit in {"email", "iban", "identifier", "url_host"}
