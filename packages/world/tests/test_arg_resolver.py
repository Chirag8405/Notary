import pytest

from notary_core.canon import sha256_hex
from notary_core.models import (
    EmailOrigin,
    FileOrigin,
    Integrity,
    Label,
    LlmOrigin,
    Origin,
    ResolvedValue,
    SpanPointer,
    UserOrigin,
    ValueRef,
)
from notary_world.cast import BILLER_IBAN, SECRET_2FA_CODE
from notary_world.executor import DefaultArgResolver

BODY = f"Amount due: 120.00 EUR. Pay to IBAN {BILLER_IBAN}."
REQUEST = "Pay my December bill"


def value(
    value_id: str,
    text: str,
    *,
    origin: Origin | None = None,
    integrity: Integrity = "untrusted",
    readers: tuple[str, ...] = ("*",),
) -> ResolvedValue:
    label = Label(
        origin=origin or EmailOrigin(kind="email"),
        integrity=integrity,
        readers=readers,
        span_pointer=None,
    )
    return ResolvedValue(
        ref=ValueRef(id=value_id, label=label, content_hash=sha256_hex(text)), unit=None, text=text
    )


def request_value() -> ResolvedValue:
    return value("v-request", REQUEST, origin=UserOrigin(kind="user"), integrity="trusted")


def bill_store() -> dict[str, ResolvedValue]:
    return {"c1.m-dec.body": value("c1.m-dec.body", BODY), "v-request": request_value()}


def resolve(raw: str, store: dict[str, ResolvedValue], unit: str | None = None) -> ResolvedValue:
    return DefaultArgResolver()(
        call_id="c2",
        tool="pay_bill",
        param="payee",
        raw=raw,
        unit="iban" if unit == "iban" else None,
        store=store,
    )


@pytest.mark.invariant("I2")
def test_rule1_returns_the_stored_value_unchanged() -> None:
    store = bill_store()
    assert resolve(BODY, store) == store["c1.m-dec.body"]


@pytest.mark.attack("A7")
def test_rule1_matches_by_canonical_form() -> None:
    store = {"x": value("x", BILLER_IBAN)}
    assert resolve(" de00acme00000000000001 ", store, "iban") == store["x"]


@pytest.mark.attack("A6")
def test_rule1_prefers_the_lowest_integrity() -> None:
    store = {
        "a": value("a", BILLER_IBAN, origin=UserOrigin(kind="user"), integrity="trusted"),
        "b": value("b", BILLER_IBAN),
    }
    assert resolve(BILLER_IBAN, store) == store["b"]


@pytest.mark.attack("A3")
def test_rule2_span_value_inherits_label_and_span() -> None:
    got = resolve(BILLER_IBAN, bill_store(), "iban")
    assert got == ResolvedValue(
        ref=ValueRef(
            id="c2.arg.payee",
            label=Label(
                origin=EmailOrigin(kind="email"),
                integrity="untrusted",
                readers=("*",),
                span_pointer=SpanPointer(source_value_id="c1.m-dec.body", start=36, end=58),
            ),
            content_hash=sha256_hex(BILLER_IBAN),
        ),
        unit="iban",
        text=BILLER_IBAN,
    )


@pytest.mark.attack("A3")
def test_rule2_from_the_user_request_is_trusted() -> None:
    got = resolve("December", bill_store())
    assert got.ref.id == "c2.arg.payee"
    assert got.text == "December"
    assert got.ref.label == Label(
        origin=UserOrigin(kind="user"),
        integrity="trusted",
        readers=("*",),
        span_pointer=SpanPointer(source_value_id="v-request", start=7, end=15),
    )


@pytest.mark.attack("A7")
def test_rule2_needs_min_match_len() -> None:
    store = {"x": value("x", "abcdef")}
    got = resolve("abc", store)
    assert got.ref.label.origin == LlmOrigin(kind="llm", context_readers=("*",))
    assert got.ref.label.span_pointer is None


@pytest.mark.attack("A5")
def test_rule3_inherits_readers_of_quoted_secrets() -> None:
    store = {
        **bill_store(),
        "c1.secrets/2fa.txt.text": value(
            "c1.secrets/2fa.txt.text",
            SECRET_2FA_CODE,
            origin=FileOrigin(kind="file"),
            readers=("user",),
        ),
    }
    raw = f"Summary: {SECRET_2FA_CODE}"
    got = resolve(raw, store)
    assert got.ref.label == Label(
        origin=LlmOrigin(kind="llm", context_readers=("user",)),
        integrity="untrusted",
        readers=("user",),
        span_pointer=None,
    )
    assert got.text == raw
    # Not a whole quote: the readers stay public, the origin records what the model had read.
    other = resolve("hello world", store).ref.label
    assert other.readers == ("*",)
    assert other.origin == LlmOrigin(kind="llm", context_readers=("user",))


@pytest.mark.invariant("I6")
def test_resolver_is_pure() -> None:
    store = bill_store()
    before = dict(store)
    first = resolve(BILLER_IBAN, store, "iban")
    assert resolve(BILLER_IBAN, store, "iban") == first
    assert store == before


@pytest.mark.invariant("I6")
def test_resolver_ignores_mapping_order() -> None:
    store = {
        "b": value("b", BILLER_IBAN),
        "a": value("a", f"IBAN {BILLER_IBAN}"),
        "c": value("c", BILLER_IBAN, integrity="trusted"),
    }
    reversed_store = dict(reversed(store.items()))
    for raw in (BILLER_IBAN, "IBAN DE00", "novel text"):
        assert resolve(raw, store, "iban") == resolve(raw, reversed_store, "iban")
