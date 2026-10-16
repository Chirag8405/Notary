from collections.abc import Callable, MutableMapping
from typing import cast

import pytest

from notary_core.canon import sha256_hex
from notary_core.gateway import ValueStore
from notary_core.models import (
    FreeMarker,
    IntentContract,
    Label,
    LlmOrigin,
    ResolvedValue,
    SessionState,
    SpanPointer,
    ToolCallProposal,
    ToolScope,
    UserOrigin,
    ValueRef,
)
from notary_core.monitor import decide
from notary_core.store import (
    InMemoryValueStore,
    ValueIdCollisionError,
    content_hash_ok,
    derive_value,
    span_resolves,
)

ValueFactory = Callable[..., ResolvedValue]

EMAIL_TEXT = "Pay to DE00ATTACKER0000000001 today"
IBAN_TEXT = "DE00ATTACKER0000000001"


def with_span(value: ResolvedValue, pointer: SpanPointer) -> ResolvedValue:
    label = value.ref.label.model_copy(update={"span_pointer": pointer})
    ref = value.ref.model_copy(update={"label": label})
    return value.model_copy(update={"ref": ref})


def send_email_decision(
    body: ResolvedValue,
    store: InMemoryValueStore,
    make_contract: Callable[..., IntentContract],
    make_scope: Callable[..., ToolScope],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
):
    contract = make_contract(
        tools=(make_scope("send_email", effect="write", params={"body": FreeMarker(kind="free")}),)
    )
    proposal = make_proposal("send_email", body=body)
    return decide(contract, proposal, store.as_mapping(), (), make_session())


@pytest.mark.invariant("I2")
def test_store_reads_are_sorted_and_complete(make_value: ValueFactory) -> None:
    store = InMemoryValueStore([make_value("b", "x"), make_value("a", "y"), make_value("c", "z")])
    assert store.ids() == ("a", "b", "c")
    assert list(store.as_mapping()) == ["a", "b", "c"]
    assert [v.ref.id for v in store.values()] == ["a", "b", "c"]
    assert len(store) == 3
    assert "a" in store
    assert "zz" not in store
    assert store.get("zz") is None
    assert store.get("a") == make_value("a", "y")


@pytest.mark.invariant("I6")
def test_with_values_returns_a_new_store(make_value: ValueFactory) -> None:
    first = make_value("a", "x")
    store = InMemoryValueStore([first])
    bigger = store.with_values([make_value("b", "y")])
    assert store.ids() == ("a",)
    assert bigger.ids() == ("a", "b")
    assert store.with_values(()).values() == store.values()


@pytest.mark.invariant("I2")
def test_identical_duplicate_is_idempotent(make_value: ValueFactory) -> None:
    value = make_value("a", "x")
    assert len(InMemoryValueStore([value, value])) == 1
    assert len(InMemoryValueStore([value]).with_values([value])) == 1


@pytest.mark.invariant("I2")
def test_colliding_id_is_rejected_and_stores_nothing(make_value: ValueFactory) -> None:
    store = InMemoryValueStore([make_value("a", "x")])
    with pytest.raises(ValueIdCollisionError, match="value id collision: a"):
        store.with_values([make_value("b", "fine"), make_value("a", "different")])
    assert store.ids() == ("a",)
    assert store.get("a") == make_value("a", "x")
    with pytest.raises(ValueIdCollisionError, match="value id collision: a"):
        InMemoryValueStore([make_value("a", "x"), make_value("a", "y")])


@pytest.mark.invariant("I6")
def test_as_mapping_is_read_only(make_value: ValueFactory) -> None:
    store = InMemoryValueStore([make_value("a", "x")])
    mapping = cast(MutableMapping[str, ResolvedValue], store.as_mapping())
    with pytest.raises(TypeError):
        mapping["x"] = make_value("x", "y")
    assert store.ids() == ("a",)


@pytest.mark.invariant("I2")
def test_store_satisfies_the_protocol_and_feeds_decide(
    make_value: ValueFactory,
    make_contract: Callable[..., IntentContract],
    make_scope: Callable[..., ToolScope],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
) -> None:
    message_id = make_value("m1", "m-dec", unit="identifier", origin="llm", integrity="untrusted")
    store: ValueStore = InMemoryValueStore([message_id])
    contract = make_contract(
        tools=(
            make_scope("read_email", effect="read", params={"message_id": FreeMarker(kind="free")}),
        )
    )
    proposal = make_proposal("read_email", message_id=message_id)
    decision = decide(contract, proposal, store.as_mapping(), (), make_session())
    assert decision.verdict == "ALLOW"
    assert [r.code for r in decision.reasons] == ["READ_ONLY_UNGATED"]


@pytest.mark.invariant("I2")
def test_content_hash_ok(make_value: ValueFactory) -> None:
    value = make_value("a", "hello")
    assert content_hash_ok(value) is True
    assert content_hash_ok(value.model_copy(update={"text": "tampered"})) is False


@pytest.mark.invariant("I2")
def test_span_resolves_matches_the_monitor(
    make_value: ValueFactory,
    make_contract: Callable[..., IntentContract],
    make_scope: Callable[..., ToolScope],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
) -> None:
    source = make_value("src", EMAIL_TEXT, origin="email", integrity="untrusted")
    store = {source.ref.id: source}
    plain = make_value("p", "x")
    assert span_resolves(plain, store) is True
    inside = with_span(plain, SpanPointer(source_value_id="src", start=7, end=29))
    assert span_resolves(inside, store) is True
    missing = with_span(plain, SpanPointer(source_value_id="nope", start=0, end=1))
    assert span_resolves(missing, store) is False
    past_end = with_span(
        plain, SpanPointer(source_value_id="src", start=0, end=len(EMAIL_TEXT) + 1)
    )
    assert span_resolves(past_end, store) is False
    backwards = with_span(plain, SpanPointer(source_value_id="src", start=9, end=3))
    assert span_resolves(backwards, store) is False
    edge = with_span(
        plain, SpanPointer(source_value_id="src", start=len(EMAIL_TEXT), end=len(EMAIL_TEXT))
    )
    assert span_resolves(edge, store) is True
    decision = send_email_decision(
        past_end,
        InMemoryValueStore([source, past_end]),
        make_contract,
        make_scope,
        make_proposal,
        make_session,
    )
    assert decision.verdict == "BLOCK"
    assert decision.reasons[-1].code == "ORIGIN_UNSOURCED"


def email_and_secret(make_value: ValueFactory) -> tuple[ResolvedValue, ResolvedValue]:
    email = make_value("email", EMAIL_TEXT, origin="email", integrity="untrusted", readers=("*",))
    secret = make_value(
        "secret", "CODE-8841", origin="file", integrity="trusted", readers=("user",)
    )
    return email, secret


@pytest.mark.invariant("I3")
def test_derive_takes_lowest_integrity_and_narrowest_readers(make_value: ValueFactory) -> None:
    email, secret = email_and_secret(make_value)
    derived = derive_value(
        [email, secret],
        value_id="d1",
        text=IBAN_TEXT,
        unit="iban",
        origin=LlmOrigin(kind="llm"),
        span_source=email.ref.id,
    )
    assert derived.ref.label == Label(
        origin=LlmOrigin(kind="llm"),
        integrity="untrusted",
        readers=("user",),
        span_pointer=SpanPointer(source_value_id="email", start=7, end=29),
    )
    assert derived.ref.id == "d1"
    assert derived.unit == "iban"
    assert derived.text == IBAN_TEXT
    assert derived.ref.content_hash == sha256_hex(IBAN_TEXT)
    assert content_hash_ok(derived)


@pytest.mark.attack("A6")
def test_derive_never_gains_integrity(make_value: ValueFactory) -> None:
    trusted = make_value("t", "abcd", integrity="trusted")
    endorsed = make_value("e", "efgh", integrity="endorsed")
    untrusted = make_value("u", "ijkl", integrity="untrusted")
    llm = LlmOrigin(kind="llm")

    def integrity_of(*inputs: ResolvedValue) -> str:
        return derive_value(
            inputs, value_id="d", text="x", unit=None, origin=llm
        ).ref.label.integrity

    assert integrity_of(trusted, endorsed) == "endorsed"
    assert integrity_of(trusted, untrusted) == "untrusted"
    first = derive_value([untrusted], value_id="d1", text="x", unit=None, origin=llm)
    second = derive_value([trusted, first], value_id="d2", text="y", unit=None, origin=llm)
    assert second.ref.label.integrity == "untrusted"


@pytest.mark.attack("A6")
def test_derive_without_span(make_value: ValueFactory) -> None:
    email, secret = email_and_secret(make_value)
    derived = derive_value(
        [email, secret], value_id="d", text="free text", unit=None, origin=UserOrigin(kind="user")
    )
    assert derived.ref.label.span_pointer is None
    assert derived.ref.label.readers == ("user",)
    assert derived.ref.label.origin == UserOrigin(kind="user")


@pytest.mark.attack("A6")
def test_derive_rejects_bad_input(make_value: ValueFactory) -> None:
    email, secret = email_and_secret(make_value)
    llm = LlmOrigin(kind="llm")
    with pytest.raises(ValueError, match="needs at least one input"):
        derive_value([], value_id="d", text="x", unit=None, origin=llm)
    with pytest.raises(ValueError, match="must be one of the inputs"):
        derive_value(
            [email], value_id="d", text="x", unit=None, origin=llm, span_source=secret.ref.id
        )
    with pytest.raises(ValueError, match="not a substring"):
        derive_value(
            [email], value_id="d", text="absent", unit=None, origin=llm, span_source=email.ref.id
        )


@pytest.mark.attack("A6")
def test_derive_uses_the_first_occurrence(make_value: ValueFactory) -> None:
    source = make_value("s", "ab ab ab", origin="email", integrity="untrusted")
    derived = derive_value(
        [source], value_id="d", text="ab", unit=None, origin=LlmOrigin(kind="llm"), span_source="s"
    )
    assert derived.ref.label.span_pointer == SpanPointer(source_value_id="s", start=0, end=2)


@pytest.mark.invariant("I2")
def test_derived_value_is_accepted_by_the_origin_step(
    make_value: ValueFactory,
    make_contract: Callable[..., IntentContract],
    make_scope: Callable[..., ToolScope],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
) -> None:
    email, _ = email_and_secret(make_value)
    derived = derive_value(
        [email],
        value_id="d",
        text=IBAN_TEXT,
        unit=None,
        origin=LlmOrigin(kind="llm"),
        span_source=email.ref.id,
    )
    store = InMemoryValueStore([email, derived])
    decision = send_email_decision(
        derived, store, make_contract, make_scope, make_proposal, make_session
    )
    assert all(r.code != "ORIGIN_UNSOURCED" for r in decision.reasons)
    assert any(r.check == "origin" and r.outcome == "pass" for r in decision.reasons)


@pytest.mark.invariant("I6")
def test_derivation_is_deterministic(make_value: ValueFactory) -> None:
    email, secret = email_and_secret(make_value)

    def build() -> ResolvedValue:
        return derive_value(
            [email, secret],
            value_id="d",
            text=IBAN_TEXT,
            unit="iban",
            origin=LlmOrigin(kind="llm"),
            span_source=email.ref.id,
        )

    assert build().model_dump_json() == build().model_dump_json()
    assert ValueRef.model_validate_json(build().ref.model_dump_json()) == build().ref
