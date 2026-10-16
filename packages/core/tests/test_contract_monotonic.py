"""Contract monotonicity (#55): no runtime step may widen the frozen contract (I5)."""

import pytest
from builders import budget, contract, sha
from hypothesis import given
from hypothesis import strategies as st

from notary_core.contract import (
    ContractWideningError,
    assert_monotonic,
    digest,
    is_narrower_or_equal,
    widening_reasons,
)
from notary_core.models import (
    EffectBudget,
    EndorseMarker,
    FreeMarker,
    IntentContract,
    LedgerMarker,
    LiteralMarker,
    Marker,
    NamedSourceMarker,
    ToolEffect,
    ToolScope,
)

LEDGER = LedgerMarker(kind="ledger", ledger="payees")
FREE = FreeMarker(kind="free")


def _scope(
    tool: str = "pay",
    params: dict[str, Marker] | None = None,
    effect: ToolEffect = "write",
    manifest: str | None = None,
) -> ToolScope:
    return ToolScope(
        tool=tool,
        params={"payee": LEDGER} if params is None else params,
        manifest_hash=sha(manifest or tool),
        effect=effect,
    )


def _with(
    base: IntentContract,
    *,
    tools: tuple[ToolScope, ...] | None = None,
    new_budget: EffectBudget | None = None,
    egress: tuple[str, ...] | None = None,
    authorized: tuple[str, ...] | None = None,
) -> IntentContract:
    return IntentContract(
        contract_id=base.contract_id,
        user_intent=base.user_intent,
        allowed_tools=base.allowed_tools if tools is None else tools,
        budget=base.budget if new_budget is None else new_budget,
        egress_hosts=base.egress_hosts if egress is None else egress,
        authorized_irreversible=(
            base.authorized_irreversible if authorized is None else authorized
        ),
    )


def _base() -> IntentContract:
    return contract(tools=(_scope(), _scope("send_email", {"to": LEDGER})), egress=("a.com",))


@pytest.mark.invariant("I5")
def test_identical_contract_is_not_a_widening() -> None:
    c = _base()
    assert widening_reasons(c, c) == ()
    assert is_narrower_or_equal(c, c)
    assert_monotonic(c, c)


@pytest.mark.invariant("I5")
def test_added_tool_is_a_widening() -> None:
    old = _base()
    new = _with(old, tools=(*old.allowed_tools, _scope("x")))
    assert widening_reasons(old, new) == ("tool added: x",)
    assert not is_narrower_or_equal(old, new)


@pytest.mark.invariant("I5")
def test_added_param_is_a_widening() -> None:
    old = _base()
    new = _with(old, tools=(_scope(params={"payee": LEDGER, "memo": FREE}), old.allowed_tools[1]))
    assert widening_reasons(old, new) == ("param added: pay.memo",)


@pytest.mark.invariant("I5")
def test_relaxed_marker_is_a_widening() -> None:
    old = _base()
    new = _with(old, tools=(_scope(params={"payee": FREE}), old.allowed_tools[1]))
    assert widening_reasons(old, new) == ("marker relaxed: pay.payee",)


@pytest.mark.invariant("I5")
def test_tightened_marker_is_allowed() -> None:
    old = _with(_base(), tools=(_scope(params={"payee": FREE}),))
    for tighter in (
        EndorseMarker(kind="endorse"),
        LEDGER,
        NamedSourceMarker(kind="named_source", source="contacts"),
        LiteralMarker(kind="literal", value="DE89"),
    ):
        new = _with(old, tools=(_scope(params={"payee": tighter}),))
        assert widening_reasons(old, new) == ()


@pytest.mark.invariant("I5")
def test_changed_literal_value_is_a_widening() -> None:
    def literal(value: str | int | bool) -> IntentContract:
        marker = LiteralMarker(kind="literal", value=value)
        return contract(tools=(_scope(params={"payee": marker}),))

    assert widening_reasons(literal("A"), literal("B")) == ("literal value changed: pay.payee",)
    assert widening_reasons(literal("A"), literal("A")) == ()
    # `1 == True` in Python, but a bool is not the same literal as an int
    assert widening_reasons(literal(1), literal(True)) == ("literal value changed: pay.payee",)


@pytest.mark.invariant("I5")
def test_changed_named_source_is_a_widening() -> None:
    def named(source: str) -> IntentContract:
        marker = NamedSourceMarker(kind="named_source", source=source)
        return contract(tools=(_scope(params={"payee": marker}),))

    assert widening_reasons(named("a"), named("b")) == ("named source changed: pay.payee",)


@pytest.mark.invariant("I5")
def test_changed_ledger_is_a_widening() -> None:
    def ledger(name: str) -> IntentContract:
        marker = LedgerMarker(kind="ledger", ledger=name)
        return contract(tools=(_scope(params={"payee": marker}),))

    assert widening_reasons(ledger("payees"), ledger("contacts")) == ("ledger changed: pay.payee",)


@pytest.mark.attack("A10")
def test_changed_manifest_hash_is_a_widening() -> None:
    old = _base()
    new = _with(old, tools=(_scope(manifest="pay-v2"), old.allowed_tools[1]))
    assert widening_reasons(old, new) == ("manifest changed: pay",)


@pytest.mark.invariant("I5")
def test_effect_widened_is_a_widening() -> None:
    # the monitor scrutinises `irreversible` most, so moving toward `read` is the widening
    old = contract(tools=(_scope(effect="irreversible"),))
    to_write = contract(tools=(_scope(effect="write"),))
    to_read = contract(tools=(_scope(effect="read"),))
    assert widening_reasons(old, to_write) == ("effect widened: pay",)
    assert widening_reasons(old, to_read) == ("effect widened: pay",)
    assert widening_reasons(to_write, to_read) == ("effect widened: pay",)


@pytest.mark.invariant("I5")
def test_effect_made_stricter_is_allowed() -> None:
    old = contract(tools=(_scope(effect="read"),))
    assert widening_reasons(old, contract(tools=(_scope(effect="write"),))) == ()
    assert widening_reasons(old, contract(tools=(_scope(effect="irreversible"),))) == ()


@pytest.mark.invariant("I5")
def test_added_irreversible_authorization_is_a_widening() -> None:
    old = contract(tools=(_scope(effect="irreversible"),))
    new = _with(old, authorized=("pay",))
    assert widening_reasons(old, new) == ("irreversible authorization added: pay",)
    assert widening_reasons(new, old) == ()


@pytest.mark.invariant("I5")
def test_added_egress_host_is_a_widening() -> None:
    old = _base()
    new = _with(old, egress=("a.com", "b.com"))
    assert widening_reasons(old, new) == ("egress host added: b.com",)
    assert widening_reasons(new, old) == ()


@pytest.mark.invariant("I5")
@pytest.mark.parametrize(
    "field",
    [
        "max_effects",
        "max_spend_cents",
        "max_egress_bytes",
        "max_call_amount_cents",
        "max_approvals",
    ],
)
def test_larger_budget_is_a_widening(field: str) -> None:
    old = _base()
    raised = old.budget.model_copy(update={field: getattr(old.budget, field) + 1})
    new = _with(old, new_budget=raised)
    assert widening_reasons(old, new) == (f"budget widened: {field}",)


@pytest.mark.invariant("I5")
def test_every_budget_field_is_compared() -> None:
    assert set(budget().model_dump()) == {
        "max_effects",
        "max_spend_cents",
        "max_egress_bytes",
        "max_call_amount_cents",
        "max_approvals",
    }


@pytest.mark.invariant("I5")
def test_changed_identity_fields_are_widenings() -> None:
    old = _base()
    other_id = old.model_copy(update={"contract_id": "c2"})
    other_intent = old.model_copy(update={"user_intent": "something else"})
    assert widening_reasons(old, other_id) == ("contract_id changed",)
    assert widening_reasons(old, other_intent) == ("user_intent changed",)


@pytest.mark.invariant("I5")
def test_smaller_budget_and_removed_tool_are_allowed() -> None:
    old = _base()
    smaller = old.budget.model_copy(update={"max_effects": 0, "max_spend_cents": 1})
    new = _with(old, tools=(old.allowed_tools[0],), new_budget=smaller, egress=())
    assert widening_reasons(old, new) == ()
    assert is_narrower_or_equal(old, new)
    # removing a param is also narrowing
    stripped = _with(old, tools=(_scope(params={}), old.allowed_tools[1]))
    assert widening_reasons(old, stripped) == ()


@pytest.mark.invariant("I5")
def test_assert_monotonic_raises_with_all_reasons() -> None:
    old = _base()
    new = _with(
        old,
        tools=(*old.allowed_tools, _scope("x")),
        egress=("a.com", "b.com"),
    )
    with pytest.raises(ContractWideningError) as error:
        assert_monotonic(old, new)
    assert error.value.reasons == ("egress host added: b.com", "tool added: x")
    assert list(error.value.reasons) == sorted(error.value.reasons)


@pytest.mark.invariant("I5")
def test_widening_reasons_does_not_mutate_inputs() -> None:
    old = _base()
    new = _with(old, tools=(*old.allowed_tools, _scope("x")))
    before = (old.model_dump_json(), new.model_dump_json())
    widening_reasons(old, new)
    assert (old.model_dump_json(), new.model_dump_json()) == before


@pytest.mark.invariant("I5")
def test_digest_is_stable_and_changes_with_content() -> None:
    c = _base()
    assert digest(c) == digest(_base())
    assert len(digest(c)) == 64
    variants = [
        c.model_copy(update={"contract_id": "c2"}),
        c.model_copy(update={"user_intent": "other"}),
        _with(c, tools=(c.allowed_tools[0],)),
        _with(c, tools=(_scope(params={"payee": FREE}), c.allowed_tools[1])),
        _with(c, tools=(_scope(effect="irreversible"), c.allowed_tools[1])),
        _with(c, tools=(_scope(manifest="v2"), c.allowed_tools[1])),
        _with(c, new_budget=c.budget.model_copy(update={"max_approvals": 99})),
        _with(c, egress=()),
    ]
    digests = {digest(v) for v in variants}
    assert digest(c) not in digests
    assert len(digests) == len(variants)


_MARKERS: tuple[Marker, ...] = (
    LiteralMarker(kind="literal", value="x"),
    NamedSourceMarker(kind="named_source", source="s"),
    LEDGER,
    EndorseMarker(kind="endorse"),
    FREE,
)
_TOOL_NAMES = ("pay", "send_email", "post_slack", "delete_email")
_PARAM_NAMES = ("a", "b", "c")
_EFFECTS: tuple[ToolEffect, ...] = ("irreversible", "write", "read")


@st.composite
def _contracts(draw: st.DrawFn) -> IntentContract:
    tools = draw(st.lists(st.sampled_from(_TOOL_NAMES), unique=True, max_size=len(_TOOL_NAMES)))
    scopes = tuple(
        _scope(
            tool,
            {
                name: draw(st.sampled_from(_MARKERS))
                for name in draw(st.sets(st.sampled_from(_PARAM_NAMES)))
            },
            draw(st.sampled_from(_EFFECTS)),
        )
        for tool in tools
    )
    irreversible = tuple(s.tool for s in scopes if s.effect == "irreversible")
    return IntentContract(
        contract_id="c",
        user_intent="intent",
        allowed_tools=scopes,
        budget=EffectBudget(
            max_effects=draw(st.integers(0, 5)),
            max_spend_cents=draw(st.integers(0, 10_000)),
            max_egress_bytes=draw(st.integers(0, 10_000)),
            max_call_amount_cents=draw(st.integers(0, 10_000)),
            max_approvals=draw(st.integers(0, 5)),
        ),
        egress_hosts=tuple(draw(st.sets(st.sampled_from(("a.com", "b.com", "c.com"))))),
        authorized_irreversible=tuple(t for t in irreversible if draw(st.booleans())),
    )


@st.composite
def _narrowed(draw: st.DrawFn, old: IntentContract) -> IntentContract:
    scopes: list[ToolScope] = []
    for s in old.allowed_tools:
        if draw(st.booleans()):
            continue  # remove the tool
        params = {
            name: draw(st.sampled_from([marker, *_stricter_than(marker)]))
            for name, marker in s.params.items()
            if draw(st.booleans())  # remove the param otherwise
        }
        stricter_effects = _EFFECTS[: _EFFECTS.index(s.effect) + 1]
        effect = draw(st.sampled_from(stricter_effects))
        scopes.append(
            ToolScope(tool=s.tool, params=params, manifest_hash=s.manifest_hash, effect=effect)
        )
    irreversible = {s.tool for s in scopes if s.effect == "irreversible"}
    return IntentContract(
        contract_id=old.contract_id,
        user_intent=old.user_intent,
        allowed_tools=tuple(scopes),
        budget=EffectBudget(
            **{
                field: draw(st.integers(0, value))
                for field, value in old.budget.model_dump().items()
            }
        ),
        egress_hosts=tuple(h for h in old.egress_hosts if draw(st.booleans())),
        authorized_irreversible=tuple(
            t for t in old.authorized_irreversible if t in irreversible and draw(st.booleans())
        ),
    )


def _stricter_than(marker: Marker) -> tuple[Marker, ...]:
    return tuple(m for m in _MARKERS if _MARKERS.index(m) < _MARKERS.index(marker))


@pytest.mark.invariant("I5")
@given(st.data())
def test_random_narrowing_is_never_a_widening(data: st.DataObject) -> None:
    old = data.draw(_contracts())
    new = data.draw(_narrowed(old))
    assert widening_reasons(old, new) == ()
    assert_monotonic(old, new)
