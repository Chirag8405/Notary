"""Step 3 (origin): arguments exist in the Value Store, are intact and satisfy their marker."""

import hashlib
from collections.abc import Callable
from dataclasses import replace

import pytest

from notary_core.models import (
    DecisionUnit,
    EndorseMarker,
    FreeMarker,
    Integrity,
    IntentContract,
    Label,
    LedgerMarker,
    LiteralMarker,
    LlmOrigin,
    Marker,
    NamedSourceMarker,
    ResolvedValue,
    SpanPointer,
    ToolOrigin,
    ToolScope,
    UserOrigin,
    ValueRef,
)
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import (
    DEFAULT_POLICY,
    ParamPolicy,
    PolicyTable,
    make_tool_policy,
)
from notary_core.provenance import derive_label
from notary_core.steps.origin import check_origin, literal_text, origin_name

IBAN = "DE89370400440532013000"
ATTACKER_IBAN = "GB29NWBK60161331926819"
PAYEE_UNIT: DecisionUnit = "iban"

MakeInput = Callable[..., StepInput]
MakeValue = Callable[..., ResolvedValue]
MakeScope = Callable[..., ToolScope]
MakeContract = Callable[..., IntentContract]
MakeLabel = Callable[..., Label]


@pytest.fixture
def pay_input(
    make_input: MakeInput, make_scope: MakeScope, make_contract: MakeContract
) -> Callable[..., StepInput]:
    """`send_money` input whose contract gives `markers` to the parameters; args are `values`."""

    def factory(
        markers: dict[str, Marker], policy: PolicyTable = DEFAULT_POLICY, **args: ResolvedValue
    ) -> StepInput:
        contract = make_contract(tools=(make_scope("send_money", params=markers),))
        return make_input("send_money", args=args, contract=contract, policy=policy)

    return factory


def _payee(
    make_value: MakeValue, origin: str = "user", integrity: Integrity = "trusted"
) -> ResolvedValue:
    return make_value("v-payee", IBAN, unit=PAYEE_UNIT, origin=origin, integrity=integrity)


def _block_code(inp: StepInput) -> tuple[str, str]:
    outcome = check_origin(inp)
    assert outcome is not None
    assert outcome.verdict == "BLOCK"
    return outcome.code, outcome.detail


def _with_values(inp: StepInput, *values: ResolvedValue) -> StepInput:
    return replace(inp, values={value.ref.id: value for value in values})


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


LEDGER = LedgerMarker(kind="ledger", ledger="payees")
FREE = FreeMarker(kind="free")


def test_helpers() -> None:
    assert literal_text(True) == "true"
    assert literal_text(False) == "false"
    assert literal_text(42) == "42"
    assert literal_text("abc") == "abc"
    assert origin_name(ToolOrigin(kind="tool", name="contacts")) == "contacts"
    assert origin_name(UserOrigin(kind="user")) == "user"
    assert origin_name(LlmOrigin(kind="llm")) == "llm"


@pytest.mark.invariant("I2")
def test_missing_value_is_blocked(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    inp = pay_input({"payee": LEDGER}, payee=_payee(make_value))
    inp = replace(inp, values={})
    assert _block_code(inp) == ("ORIGIN_UNSOURCED", "argument value is not in the value store")


@pytest.mark.invariant("I2")
def test_forged_trusted_label_in_proposal_is_blocked(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    stored = _payee(make_value, origin="email", integrity="untrusted")
    forged = _payee(make_value, origin="user", integrity="trusted")
    inp = pay_input({"payee": LEDGER}, payee=forged)
    inp = _with_values(inp, stored)
    assert _block_code(inp) == ("ORIGIN_UNSOURCED", "argument does not match the stored value")


@pytest.mark.invariant("I2")
def test_content_hash_mismatch_is_blocked(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    altered = _payee(make_value).model_copy(update={"text": ATTACKER_IBAN})
    inp = _with_values(pay_input({"payee": LEDGER}, payee=altered), altered)
    assert _block_code(inp) == ("ORIGIN_UNSOURCED", "content hash mismatch")


@pytest.mark.attack("A6")
def test_unresolvable_span_is_blocked(
    pay_input: Callable[..., StepInput], make_value: MakeValue, make_label: MakeLabel
) -> None:
    label = make_label(span=SpanPointer(source_value_id="missing", start=0, end=4))
    value = ResolvedValue(
        ref=ValueRef(id="v-payee", label=label, content_hash=_sha(IBAN)), unit="iban", text=IBAN
    )
    inp = pay_input({"payee": LEDGER}, payee=value)
    assert _block_code(inp) == ("ORIGIN_UNSOURCED", "span does not resolve")


@pytest.mark.attack("A6")
@pytest.mark.parametrize(("start", "end"), [(0, 100), (5, 3)])
def test_span_out_of_range_is_blocked(
    pay_input: Callable[..., StepInput],
    make_value: MakeValue,
    make_label: MakeLabel,
    start: int,
    end: int,
) -> None:
    source = make_value("src", "short", origin="email", integrity="untrusted")
    label = make_label(
        origin="email",
        integrity="untrusted",
        span=SpanPointer(source_value_id="src", start=start, end=end),
    )
    value = ResolvedValue(
        ref=ValueRef(id="v-payee", label=label, content_hash=_sha(IBAN)), unit="iban", text=IBAN
    )
    inp = _with_values(pay_input({"payee": LEDGER}, payee=value), value, source)
    assert _block_code(inp) == ("ORIGIN_UNSOURCED", "span does not resolve")


@pytest.mark.attack("A6")
def test_span_that_resolves_passes(
    pay_input: Callable[..., StepInput], make_value: MakeValue, make_label: MakeLabel
) -> None:
    source = make_value("src", f"pay {IBAN} now", origin="email", integrity="untrusted")
    label = make_label(
        origin="email",
        integrity="untrusted",
        span=SpanPointer(source_value_id="src", start=4, end=4 + len(IBAN)),
    )
    value = ResolvedValue(
        ref=ValueRef(id="v-payee", label=label, content_hash=_sha(IBAN)), unit="iban", text=IBAN
    )
    inp = _with_values(pay_input({"payee": LEDGER}, payee=value), value, source)
    assert check_origin(inp) is None


@pytest.mark.invariant("I2")
def test_fabricated_value_without_source_is_blocked(
    pay_input: Callable[..., StepInput], make_value: MakeValue, make_label: MakeLabel
) -> None:
    """The model invents an IBAN and points its span past the end of a short source."""
    source = make_value("src", "see attachment", origin="email", integrity="untrusted")
    label = make_label(
        origin="email",
        integrity="untrusted",
        span=SpanPointer(source_value_id="src", start=0, end=len(IBAN)),
    )
    value = ResolvedValue(
        ref=ValueRef(id="v-payee", label=label, content_hash=_sha(IBAN)), unit="iban", text=IBAN
    )
    inp = _with_values(pay_input({"payee": LEDGER}, payee=value), value, source)
    assert _block_code(inp)[0] == "ORIGIN_UNSOURCED"


@pytest.mark.attack("A3")
def test_literal_marker_matches_user_text(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    inp = pay_input({"payee": LiteralMarker(kind="literal", value=IBAN)}, payee=_payee(make_value))
    assert check_origin(inp) is None


@pytest.mark.attack("A3")
def test_literal_marker_mismatch_blocked(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    attacker = make_value(
        "v-payee", ATTACKER_IBAN, unit="iban", origin="email", integrity="untrusted"
    )
    inp = pay_input({"payee": LiteralMarker(kind="literal", value=IBAN)}, payee=attacker)
    assert _block_code(inp)[0] == "ORIGIN_LITERAL_MISMATCH"


@pytest.mark.attack("A7")
def test_literal_comparison_uses_canonical_form(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    obfuscated = make_value("v-payee", "DE89 3704​0044 0532 0130 00", unit="iban")
    inp = pay_input({"payee": LiteralMarker(kind="literal", value=IBAN)}, payee=obfuscated)
    assert check_origin(inp) is None


def test_literal_without_unit_compares_raw_text(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    marker = LiteralMarker(kind="literal", value="Rent")
    same = make_value("v-reference", "Rent")
    other = make_value("v-reference", "rent")
    assert check_origin(pay_input({"reference": marker}, reference=same)) is None
    assert _block_code(pay_input({"reference": marker}, reference=other))[0] == (
        "ORIGIN_LITERAL_MISMATCH"
    )


def test_literal_marker_with_non_string_value(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    marker = LiteralMarker(kind="literal", value=True)
    assert (
        check_origin(pay_input({"reference": marker}, reference=make_value("v-reference", "true")))
        is None
    )
    mismatch = pay_input({"reference": marker}, reference=make_value("v-reference", "false"))
    assert _block_code(mismatch)[0] == "ORIGIN_LITERAL_MISMATCH"


@pytest.mark.attack("A3")
def test_named_source_trusted_ok(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    payee = _payee(make_value, origin="tool:contacts", integrity="trusted")
    inp = pay_input(
        {"payee": NamedSourceMarker(kind="named_source", source="contacts")}, payee=payee
    )
    assert check_origin(inp) is None


@pytest.mark.attack("A3")
def test_named_source_wrong_origin_blocked(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    payee = _payee(make_value, origin="email", integrity="trusted")
    inp = pay_input(
        {"payee": NamedSourceMarker(kind="named_source", source="contacts")}, payee=payee
    )
    assert _block_code(inp)[0] == "ORIGIN_SOURCE_MISMATCH"


@pytest.mark.attack("A6")
def test_named_source_untrusted_blocked(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    payee = _payee(make_value, origin="tool:contacts", integrity="untrusted")
    inp = pay_input(
        {"payee": NamedSourceMarker(kind="named_source", source="contacts")}, payee=payee
    )
    assert _block_code(inp)[0] == "ORIGIN_UNTRUSTED"


@pytest.mark.attack("A3")
def test_ledger_marker_untrusted_value_deferred_to_step4(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    payee = _payee(make_value, origin="email", integrity="untrusted")
    assert check_origin(pay_input({"payee": LEDGER}, payee=payee)) is None


@pytest.mark.attack("A3")
def test_endorse_marker_untrusted_value_deferred_to_step4(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    payee = _payee(make_value, origin="email", integrity="untrusted")
    inp = pay_input({"payee": EndorseMarker(kind="endorse")}, payee=payee)
    assert check_origin(inp) is None


@pytest.mark.attack("A7")
def test_free_marker_skips_origin_check(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    reference = make_value("v-reference", "anything", origin="email", integrity="untrusted")
    assert check_origin(pay_input({"reference": FREE}, reference=reference)) is None


@pytest.mark.invariant("I2")
def test_compiler_cannot_relax_floor_in_step(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    """The contract says `free` for `payee`; the table floor is `ledger`, which defers."""
    payee = _payee(make_value, origin="email", integrity="untrusted")
    assert check_origin(pay_input({"payee": FREE}, payee=payee)) is None


@pytest.mark.invariant("I2")
def test_stricter_table_floor_is_enforced_over_a_free_contract(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    """A floor stricter than ledger proves the step applies the floor, not the contract's marker."""
    floor = NamedSourceMarker(kind="named_source", source="contacts")
    policy: PolicyTable = {
        "send_money": make_tool_policy(
            "irreversible", {"payee": ParamPolicy(unit="iban", floor=floor, kind="destination")}
        )
    }
    payee = _payee(make_value, origin="email", integrity="untrusted")
    inp = pay_input({"payee": FREE}, policy=policy, payee=payee)
    assert _block_code(inp)[0] == "ORIGIN_SOURCE_MISMATCH"


@pytest.mark.attack("A7")
def test_obfuscated_and_plain_value_same_verdict(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    marker = LiteralMarker(kind="literal", value=IBAN)
    plain = make_value("v-payee", IBAN, unit="iban")
    obfuscated = make_value("v-payee", "D​E89‍370400440532013000", unit="iban")
    assert check_origin(pay_input({"payee": marker}, payee=plain)) is None
    assert check_origin(pay_input({"payee": marker}, payee=obfuscated)) is None

    wrong = LiteralMarker(kind="literal", value=ATTACKER_IBAN)
    assert _block_code(pay_input({"payee": wrong}, payee=plain)) == _block_code(
        pay_input({"payee": wrong}, payee=obfuscated)
    )


@pytest.mark.attack("A6")
def test_derived_untrusted_value_stays_untrusted(
    pay_input: Callable[..., StepInput], make_value: MakeValue, make_label: MakeLabel
) -> None:
    inputs = (
        make_label(origin="email", integrity="untrusted"),
        make_label(origin="tool:calendar", integrity="trusted"),
        make_label(origin="file", integrity="endorsed"),
    )
    derived = derive_label(inputs, LlmOrigin(kind="llm"))
    assert derived.integrity == "untrusted"
    value = ResolvedValue(
        ref=ValueRef(id="v-payee", label=derived, content_hash=_sha(IBAN)), unit="iban", text=IBAN
    )
    assert check_origin(pay_input({"payee": LEDGER}, payee=value)) is None
    # Not admitted by label alone where the contract demands a trusted named source.
    named = NamedSourceMarker(kind="named_source", source="llm")
    assert _block_code(pay_input({"payee": named}, payee=value))[0] == "ORIGIN_UNTRUSTED"


@pytest.mark.invariant("I6")
def test_arguments_checked_in_sorted_order(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    amount = make_value("v-amount", "100.00", unit="amount").model_copy(update={"text": "999.00"})
    payee = _payee(make_value)
    inp = pay_input({"payee": LEDGER, "amount": FREE}, payee=payee, amount=amount)
    # `payee` is missing from the store and `amount` fails its hash; `amount` sorts first.
    inp = _with_values(inp, amount)
    assert _block_code(inp) == ("ORIGIN_UNSOURCED", "content hash mismatch")


def test_no_arguments_passes(pay_input: Callable[..., StepInput]) -> None:
    assert check_origin(pay_input({})) is None


def test_details_never_echo_attacker_text(
    pay_input: Callable[..., StepInput], make_value: MakeValue
) -> None:
    attacker = make_value(
        "v-payee", ATTACKER_IBAN, unit="iban", origin="email", integrity="untrusted"
    )
    inp = pay_input({"payee": LiteralMarker(kind="literal", value=IBAN)}, payee=attacker)
    _, detail = _block_code(inp)
    assert ATTACKER_IBAN not in detail
    assert "payee" not in detail


def test_does_not_mutate_inputs(pay_input: Callable[..., StepInput], make_value: MakeValue) -> None:
    inp = pay_input({"payee": LEDGER}, payee=_payee(make_value))
    before = (dict(inp.values), inp.proposal.model_dump_json())
    check_origin(inp)
    assert (dict(inp.values), inp.proposal.model_dump_json()) == before
