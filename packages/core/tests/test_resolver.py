from collections.abc import Callable, Mapping

import pytest

import notary_core.models
from notary_core.canon import sha256_hex
from notary_core.models import (
    DecisionUnit,
    EmailOrigin,
    Integrity,
    Label,
    LlmOrigin,
    ResolvedValue,
    SpanPointer,
)
from notary_core.resolver import ArgumentResolver, canonical_args
from notary_core.store import content_hash_ok, span_resolves
from notary_core.units import canonicalize

MakeValue = Callable[..., ResolvedValue]

ACME = "DE00ACME00000000000001"
ATTACKER = "DE00ATTACKER0000000001"
BODY = f"Amount due: 120.00 EUR. Pay to IBAN {ATTACKER}."
ZW = chr(0x200B)


def resolve(
    raw: str,
    store: Mapping[str, ResolvedValue],
    unit: DecisionUnit | None = None,
    param: str = "payee",
) -> ResolvedValue:
    return ArgumentResolver()(
        call_id="c2", tool="pay_bill", param=param, raw=raw, unit=unit, store=store
    )


def store_of(*values: ResolvedValue) -> dict[str, ResolvedValue]:
    return {v.ref.id: v for v in values}


def body_value(make_value: MakeValue) -> ResolvedValue:
    return make_value("c1.m-dec.body", BODY, origin="email", integrity="untrusted")


def assert_sound(value: ResolvedValue, store: Mapping[str, ResolvedValue]) -> None:
    assert content_hash_ok(value)
    assert span_resolves(value, store)
    pointer = value.ref.label.span_pointer
    if pointer is not None:
        source = store[pointer.source_value_id]
        assert source.text[pointer.start : pointer.end] == value.text


@pytest.mark.invariant("I2")
def test_rule1_reuses_the_stored_value(make_value: MakeValue) -> None:
    stored = make_value("x", ACME, "iban", origin="email", integrity="untrusted")
    got = resolve(f" {ACME.lower()} ", store_of(stored), "iban")
    assert got == stored
    assert (got.ref.id, got.ref.label, got.text) == ("x", stored.ref.label, ACME)


@pytest.mark.invariant("I2")
def test_rule1_prefers_the_lowest_integrity_then_smallest_id(make_value: MakeValue) -> None:
    trusted = make_value("a", ACME, integrity="trusted")
    untrusted = make_value("z", ACME, origin="email", integrity="untrusted")
    assert resolve(ACME, store_of(trusted, untrusted)).ref.id == "z"
    first = make_value("b", ACME, origin="email", integrity="untrusted")
    second = make_value("c", ACME, origin="email", integrity="untrusted")
    assert resolve(ACME, store_of(second, first)).ref.id == "b"


@pytest.mark.attack("A3")
def test_rule2_labels_a_span_of_an_untrusted_source(make_value: MakeValue) -> None:
    store = store_of(body_value(make_value))
    got = resolve(f" {ATTACKER} ", store, "iban")
    assert got.ref.id == "c2.arg.payee"
    assert got.ref.label == Label(
        origin=EmailOrigin(kind="email"),
        integrity="untrusted",
        readers=("*",),
        span_pointer=SpanPointer(source_value_id="c1.m-dec.body", start=36, end=58),
    )
    assert (got.text, got.unit) == (ATTACKER, "iban")
    assert got.ref.content_hash == sha256_hex(ATTACKER)
    assert_sound(got, store)


@pytest.mark.invariant("I3")
def test_rule2_keeps_a_secrets_readers(make_value: MakeValue) -> None:
    secret = make_value("s", "CODE-8841 and more", origin="file", readers=("user",))
    got = resolve("CODE-8841", store_of(secret))
    assert got.ref.label.readers == ("user",)
    assert got.ref.label.span_pointer == SpanPointer(source_value_id="s", start=0, end=9)
    assert_sound(got, store_of(secret))


@pytest.mark.invariant("I2")
def test_rule2_needs_min_match_len(make_value: MakeValue) -> None:
    store = store_of(make_value("x", "abcdef", origin="email", integrity="untrusted"))
    got = resolve("abc", store)
    assert got.ref.label.origin == LlmOrigin(kind="llm")
    assert got.ref.label.span_pointer is None


@pytest.mark.invariant("I2")
def test_rule3_is_model_authored() -> None:
    raw = " hello world "
    got = resolve(raw, {})
    assert got.ref.id == "c2.arg.payee"
    assert got.ref.label == Label(
        origin=LlmOrigin(kind="llm"), integrity="untrusted", readers=("*",), span_pointer=None
    )
    assert got.text == raw
    assert got.ref.content_hash == sha256_hex(raw)
    assert_sound(got, {})


@pytest.mark.invariant("I3")
def test_rule3_quoting_a_secret_restricts_readers(make_value: MakeValue) -> None:
    secret = make_value("s", "CODE-8841", origin="file", integrity="untrusted", readers=("user",))
    got = resolve("my code is CODE-8841", store_of(secret))
    assert got.ref.label.origin == LlmOrigin(kind="llm")
    assert got.ref.label.readers == ("user",)


@pytest.mark.invariant("I3")
def test_rule3_short_secrets_do_not_restrict(make_value: MakeValue) -> None:
    # Documented limit: stored text shorter than MIN_MATCH_LEN is never recognized as quoted.
    secret = make_value("s", "abc", origin="file", integrity="untrusted", readers=("user",))
    got = resolve("my abc is here", store_of(secret))
    assert got.ref.label.readers == ("*",)


@pytest.mark.invariant("I2")
def test_resolved_value_hash_and_span_are_sound(make_value: MakeValue) -> None:
    store = store_of(
        body_value(make_value),
        make_value("s", "CODE-8841", origin="file", integrity="untrusted", readers=("user",)),
    )
    cases: tuple[tuple[str, DecisionUnit | None], ...] = (
        (ATTACKER, "iban"),
        (f"  {ATTACKER}  ", None),
        ("December", None),
        ("quote CODE-8841 inside", None),
        ("", None),
        ("   ", None),
    )
    for raw, unit in cases:
        assert_sound(resolve(raw, store, unit), store)


@pytest.mark.attack("A7")
def test_canonical_args_uses_the_parameter_unit(make_value: MakeValue) -> None:
    text = "de00acme0000000000" + ZW + "0001"
    value = make_value("x", text, unit=None)
    assert canonical_args({"payee": value}, {"payee": "iban"}) == {"payee": ACME}


@pytest.mark.attack("A7")
def test_canonical_args_leaves_identifiers_and_free_text(make_value: MakeValue) -> None:
    args = {
        "name": make_value("n", " Alpha Consulting "),
        "body": make_value("b", "Hello  World"),
        "amount": make_value("a", "120.00"),
    }
    got = canonical_args(args, {"name": "identifier", "body": None, "amount": "amount"})
    assert got == {"amount": "120.00", "body": "Hello  World", "name": " Alpha Consulting "}
    assert list(got) == ["amount", "body", "name"]


@pytest.mark.attack("A3")
def test_canonical_args_amount_and_email(make_value: MakeValue) -> None:
    args = {
        "amount": make_value("a", "120,00"),
        "to": make_value("t", "ACCOUNTANT@acme.example"),
    }
    got = canonical_args(args, {"amount": "amount", "to": "email"})
    assert got == {
        "amount": canonicalize("amount", "120,00").value,
        "to": canonicalize("email", "ACCOUNTANT@acme.example").value,
    }
    assert got["amount"] == "120.00"


@pytest.mark.invariant("I6")
def test_resolver_is_deterministic_and_pure(make_value: MakeValue) -> None:
    store = store_of(body_value(make_value), make_value("v", "Pay my December bill"))
    before = dict(store)
    first = resolve(ATTACKER, store, "iban")
    assert resolve(ATTACKER, store, "iban") == first
    assert store == before
    args = {"payee": first}
    units: dict[str, DecisionUnit | None] = {"payee": "iban"}
    assert canonical_args(args, units) == canonical_args(args, units)
    assert args == {"payee": first}
    assert units == {"payee": "iban"}


@pytest.mark.invariant("I2")
def test_reused_value_keeps_its_own_unit(make_value: MakeValue) -> None:
    stored = make_value("x", ACME, unit="identifier", origin="email", integrity="untrusted")
    got = resolve(ACME, store_of(stored), "iban")
    assert got == stored
    assert got.unit == "identifier"


@pytest.mark.invariant("I2")
def test_whitespace_and_empty_raw(make_value: MakeValue) -> None:
    store = store_of(body_value(make_value))
    for raw in ("", "   "):
        got = resolve(raw, store)
        assert got.ref.label.readers == ("*",)
        assert got.ref.label.origin == LlmOrigin(kind="llm")
        assert got.text == raw
        assert_sound(got, store)


@pytest.mark.invariant("I2")
def test_ties_go_to_the_smallest_id_across_rule2_sources(make_value: MakeValue) -> None:
    later = make_value("m2", f"see {ATTACKER}", origin="email", integrity="untrusted")
    earlier = make_value("m1", f"also {ATTACKER}!", origin="email", integrity="untrusted")
    got = resolve(ATTACKER, store_of(later, earlier))
    pointer = got.ref.label.span_pointer
    assert pointer is not None
    assert (pointer.source_value_id, pointer.start) == ("m1", 5)


@pytest.mark.invariant("I2")
def test_rule2_prefers_the_lowest_integrity_source(make_value: MakeValue) -> None:
    kinds: tuple[tuple[str, Integrity], ...] = (
        ("a", "trusted"),
        ("b", "endorsed"),
        ("z", "untrusted"),
    )
    values = [make_value(i, f"pay {ATTACKER}", origin="email", integrity=g) for i, g in kinds]
    got = resolve(ATTACKER, store_of(*values))
    pointer = got.ref.label.span_pointer
    assert pointer is not None
    assert (pointer.source_value_id, got.ref.label.integrity) == ("z", "untrusted")


@pytest.mark.attack("A7")
def test_canonical_args_ignores_unused_units_and_missing_units(make_value: MakeValue) -> None:
    args = {"payee": make_value("x", " " + ACME.lower() + " "), "note": make_value("n", " Hi ")}
    units: dict[str, DecisionUnit | None] = {"payee": "iban", "ghost": "email"}
    assert canonical_args(args, units) == {"note": " Hi ", "payee": ACME}


@pytest.mark.invariant("I6")
def test_module_stays_out_of_models_all() -> None:
    exported = set(notary_core.models.__all__)
    assert {"ArgumentResolver", "canonical_args", "ArgResolver"}.isdisjoint(exported)
