"""Policy machinery (#52): floors cannot be relaxed, unknown tools and params fail closed."""

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from notary_core.models import (
    DecisionUnit,
    EndorseMarker,
    FreeMarker,
    LedgerMarker,
    LiteralMarker,
    Marker,
    NamedSourceMarker,
    ToolEffect,
)
from notary_core.policy.sensitive_params import (
    DEFAULT_POLICY,
    EFFECT_STRICTNESS,
    UNKNOWN_PARAM,
    ParamBinding,
    ParamPolicy,
    PolicyTable,
    ToolPolicy,
    effective_effect,
    effective_marker,
    make_tool_policy,
    marker_rank,
    merge_with_compiler_markers,
    param_policy,
    stricter_effect,
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


# covers: I2
def test_compiler_cannot_relax_floor() -> None:
    floor = LedgerMarker(kind="ledger", ledger="vendors")
    assert merge_with_compiler_markers(floor, FreeMarker(kind="free")) == floor


# covers: I2
def test_compiler_can_tighten_floor() -> None:
    proposed = LedgerMarker(kind="ledger", ledger="vendors")
    assert merge_with_compiler_markers(EndorseMarker(kind="endorse"), proposed) == proposed


# covers: I2
def test_equal_rank_keeps_proposed_marker() -> None:
    proposed = NamedSourceMarker(kind="named_source", source="contacts")
    floor = NamedSourceMarker(kind="named_source", source="other")
    assert merge_with_compiler_markers(floor, proposed) == proposed


# covers: I2
def test_equal_rank_ledger_keeps_floor() -> None:
    floor = LedgerMarker(kind="ledger", ledger="a")
    assert merge_with_compiler_markers(floor, LedgerMarker(kind="ledger", ledger="b")) == floor


# covers: I2
def test_none_proposed_returns_floor() -> None:
    floor = EndorseMarker(kind="endorse")
    assert merge_with_compiler_markers(floor, None) == floor


# covers: I2
@given(floor=markers, proposed=st.none() | markers)
def test_merge_never_returns_looser_than_floor(floor: Marker, proposed: Marker | None) -> None:
    assert marker_rank(merge_with_compiler_markers(floor, proposed)) <= marker_rank(floor)


@given(floor=markers, proposed=markers)
def test_merge_is_deterministic_and_pure(floor: Marker, proposed: Marker) -> None:
    first = merge_with_compiler_markers(floor, proposed)
    assert merge_with_compiler_markers(floor, proposed) == first
    assert first in (floor, proposed)


# covers: I2
def test_unknown_tool_defaults_to_irreversible() -> None:
    assert effective_effect({}, "x", None) == "irreversible"


# covers: I2
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


# covers: I2
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


# covers: I2
def test_effective_marker_applies_table_floor() -> None:
    floor = LedgerMarker(kind="ledger", ledger="vendors")
    table = _table("write", floor)
    assert effective_marker(table, "pay", "to", FreeMarker(kind="free")) == floor
    assert effective_marker({}, "t", "p", FreeMarker(kind="free")) == EndorseMarker(kind="endorse")


def test_default_policy_is_read_only() -> None:
    with pytest.raises(TypeError):
        DEFAULT_POLICY["x"] = make_tool_policy("read", {})  # type: ignore[index]


# covers: model
def test_literal_floor_rejected() -> None:
    with pytest.raises(ValidationError):
        ParamPolicy(unit=None, floor=LiteralMarker(kind="literal", value="x"), kind="other")


# covers: model, I2
def test_empty_ledger_floor_rejected() -> None:
    with pytest.raises(ValidationError):
        ParamPolicy(unit=None, floor=LedgerMarker(kind="ledger", ledger=""), kind="other")


def _param(unit: DecisionUnit | None = "iban") -> ParamPolicy:
    return ParamPolicy(unit=unit, floor=EndorseMarker(kind="endorse"), kind="destination")


# covers: model
def test_toolpolicy_duplicate_param_names_rejected() -> None:
    binding = ParamBinding(name="to", policy=_param())
    with pytest.raises(ValidationError):
        ToolPolicy(effect="write", params=(binding, binding))


# covers: model
def test_make_tool_policy_is_order_independent() -> None:
    a = make_tool_policy("write", {"to": _param(), "cc": _param("email")})
    b = make_tool_policy("write", {"cc": _param("email"), "to": _param()})
    assert a.model_dump_json() == b.model_dump_json()
    assert [binding.name for binding in a.params] == ["cc", "to"]


# covers: I2
def test_toolpolicy_params_immutable() -> None:
    tool = make_tool_policy("write", {"to": _param()})
    with pytest.raises(ValidationError):
        tool.params = ()
    with pytest.raises(ValidationError):
        tool.params[0].name = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        tool.params[0] = tool.params[0]  # type: ignore[index]
