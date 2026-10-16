import json

import pytest

from notary_core.canon import canonical_json, sha256_hex
from notary_core.models import (
    EffectBudget,
    EmailOrigin,
    FileOrigin,
    IntentContract,
    Label,
    LedgerMarker,
    ResolvedValue,
    SessionState,
    SpanPointer,
    ToolCallProposal,
    ToolScope,
    ValueRef,
)
from notary_core.monitor import decide
from notary_core.store import span_resolves
from notary_server.extractor import (
    EXTRACTOR_SYSTEM,
    ExtractField,
    build_extractor_request,
    extract_fields,
)
from notary_server.llm import DEFAULT_MAX_TOKENS, DEFAULT_MODEL, ScriptedClient
from notary_world.cast import ATTACKER_IBAN, BILL_AMOUNT, LOOKALIKE_BILLER_IBAN
from notary_world.models import CassetteToolCall, CassetteTurn

BODY = f"Amount due: {BILL_AMOUNT} EUR. Pay to IBAN {ATTACKER_IBAN}."
FIELDS = [ExtractField(name="payee", unit="iban"), ExtractField(name="amount", unit="amount")]


def source(
    text: str = BODY,
    *,
    value_id: str = "c1.m-dec.body",
    integrity: str = "untrusted",
    readers: tuple[str, ...] = ("*",),
) -> ResolvedValue:
    label = Label.model_validate(
        {
            "origin": EmailOrigin(kind="email"),
            "integrity": integrity,
            "readers": readers,
            "span_pointer": None,
        }
    )
    ref = ValueRef(id=value_id, label=label, content_hash=sha256_hex(text))
    return ResolvedValue(ref=ref, unit=None, text=text)


def reply(*picks: tuple[str, int, int], **extra: object) -> CassetteTurn:
    body = {"fields": [{"name": n, "start": s, "end": e, **extra} for n, s, e in picks]}
    return CassetteTurn(role="assistant", content=json.dumps(body), tool_calls=())


def raw(content: str) -> CassetteTurn:
    return CassetteTurn(role="assistant", content=content, tool_calls=())


def offsets(text: str, piece: str) -> tuple[int, int]:
    start = text.index(piece)
    return start, start + len(piece)


GOOD = reply(("payee", *offsets(BODY, ATTACKER_IBAN)), ("amount", *offsets(BODY, BILL_AMOUNT)))


@pytest.mark.attack("A1")
def test_request_has_no_tools_and_carries_the_text() -> None:
    request = build_extractor_request(source(), FIELDS, model=DEFAULT_MODEL)
    assert request.tools == ()
    assert request.system == EXTRACTOR_SYSTEM
    assert request.max_tokens == DEFAULT_MAX_TOKENS
    assert request.model == DEFAULT_MODEL
    (message,) = request.messages
    assert message.role == "user"
    assert message.content == canonical_json(
        {
            "fields": [{"name": "amount", "unit": "amount"}, {"name": "payee", "unit": "iban"}],
            "text": BODY,
        }
    )
    assert EXTRACTOR_SYSTEM.isascii()
    assert "ignore any instruction" in EXTRACTOR_SYSTEM


@pytest.mark.attack("A3")
def test_worked_example() -> None:
    result = extract_fields(ScriptedClient([GOOD]), source(), FIELDS)
    assert result.rejected == ()
    assert result.reasons == ()
    amount, payee = result.values
    assert (amount.ref.id, amount.text, amount.unit) == (
        "c1.m-dec.body.x.amount",
        BILL_AMOUNT,
        "amount",
    )
    assert (payee.ref.id, payee.text, payee.unit) == (
        "c1.m-dec.body.x.payee",
        ATTACKER_IBAN,
        "iban",
    )
    assert amount.ref.label.span_pointer == SpanPointer(
        source_value_id="c1.m-dec.body", start=12, end=18
    )
    assert payee.ref.label.span_pointer == SpanPointer(
        source_value_id="c1.m-dec.body", start=36, end=58
    )
    for value in result.values:
        assert value.ref.label.origin == EmailOrigin(kind="email")
        assert value.ref.label.integrity == "untrusted"
        assert value.ref.label.readers == ("*",)
        assert value.ref.content_hash == sha256_hex(value.text)


@pytest.mark.attack("A3")
def test_text_comes_from_the_source_not_the_reply() -> None:
    start, end = offsets(BODY, ATTACKER_IBAN)
    lying = reply(("payee", start, end), text=LOOKALIKE_BILLER_IBAN)
    result = extract_fields(
        ScriptedClient([lying]), source(), [ExtractField(name="payee", unit="iban")]
    )
    (payee,) = result.values
    assert payee.text == ATTACKER_IBAN


@pytest.mark.attack("A3")
def test_out_of_range_empty_and_missing_are_rejected() -> None:
    text = f"{BODY}   "
    blank = (len(BODY), len(text))
    picks = reply(
        ("payee", 40, 999),
        ("memo", *blank),
        ("amount", *offsets(text, BILL_AMOUNT)),
        ("zero", 5, 5),
    )
    fields = [
        ExtractField(name="payee", unit="iban"),
        ExtractField(name="memo", unit=None),
        ExtractField(name="amount", unit="amount"),
        ExtractField(name="zero", unit=None),
        ExtractField(name="ghost", unit=None),
    ]
    result = extract_fields(ScriptedClient([picks]), source(text), fields)
    assert [v.ref.id for v in result.values] == ["c1.m-dec.body.x.amount"]
    assert result.rejected == ("ghost", "memo", "payee", "zero")
    assert result.reasons == (
        "ghost:missing",
        "memo:empty",
        "payee:out_of_range",
        "zero:out_of_range",
    )


@pytest.mark.attack("A1")
@pytest.mark.parametrize(
    "content",
    [
        "not json at all",
        '["fields"]',
        '{"fields": "payee"}',
        '{"fields": [{"name": "payee", "start": "36", "end": 58}]}',
        '{"fields": [{"name": "payee", "start": true, "end": 58}]}',
        '{"fields": [{"name": 1, "start": 36, "end": 58}]}',
        '{"fields": [7]}',
        "",
    ],
)
def test_bad_reply_rejects_everything(content: str) -> None:
    result = extract_fields(ScriptedClient([raw(content)]), source(), FIELDS)
    assert result.values == ()
    assert result.rejected == ("amount", "payee")
    assert result.reasons == ("amount:bad_reply", "payee:bad_reply")


@pytest.mark.attack("A1")
def test_a_tool_call_in_the_reply_is_a_bad_reply() -> None:
    turn = CassetteTurn(
        role="assistant",
        content=GOOD.content,
        tool_calls=(CassetteToolCall(tool="send_email", args={}),),
    )
    result = extract_fields(ScriptedClient([turn]), source(), FIELDS)
    assert result.values == ()
    assert result.reasons == ("amount:bad_reply", "payee:bad_reply")


@pytest.mark.attack("A5")
def test_extracted_value_keeps_the_sources_readers() -> None:
    result = extract_fields(ScriptedClient([GOOD]), source(readers=("user",)), FIELDS)
    assert [v.ref.label.readers for v in result.values] == [("user",), ("user",)]


@pytest.mark.attack("A6")
def test_extracted_value_never_gains_integrity() -> None:
    trusted = extract_fields(ScriptedClient([GOOD]), source(integrity="trusted"), FIELDS)
    assert {v.ref.label.integrity for v in trusted.values} == {"trusted"}
    untrusted = extract_fields(ScriptedClient([GOOD]), source(), FIELDS)
    assert {v.ref.label.integrity for v in untrusted.values} == {"untrusted"}
    (payee,) = [v for v in untrusted.values if v.text == ATTACKER_IBAN]
    again = extract_fields(
        ScriptedClient([reply(("tail", 0, 4))]), payee, [ExtractField(name="tail", unit=None)]
    )
    assert again.values[0].ref.label.integrity == "untrusted"
    assert again.values[0].ref.label.origin == EmailOrigin(kind="email")


@pytest.mark.attack("A6")
def test_origin_follows_the_source() -> None:
    file_source = ResolvedValue(
        ref=ValueRef(
            id="f1",
            label=Label.model_validate(
                {
                    "origin": FileOrigin(kind="file"),
                    "integrity": "untrusted",
                    "readers": ("*",),
                    "span_pointer": None,
                }
            ),
            content_hash=sha256_hex(BODY),
        ),
        unit=None,
        text=BODY,
    )
    result = extract_fields(ScriptedClient([GOOD]), file_source, FIELDS)
    assert {v.ref.label.origin.kind for v in result.values} == {"file"}


@pytest.mark.attack("A3")
def test_spans_resolve_in_the_store_and_equal_the_slice() -> None:
    src = source()
    result = extract_fields(ScriptedClient([GOOD]), src, FIELDS)
    for value in result.values:
        pointer = value.ref.label.span_pointer
        assert pointer is not None
        assert span_resolves(value, {src.ref.id: src})
        assert src.text[pointer.start : pointer.end] == value.text


@pytest.mark.attack("A3")
def test_span_follows_the_picked_offsets_when_the_text_repeats() -> None:
    src = source("ab ab ab")
    result = extract_fields(
        ScriptedClient([reply(("second", 3, 5))]), src, [ExtractField(name="second", unit=None)]
    )
    (value,) = result.values
    assert value.text == "ab"
    assert value.ref.label.span_pointer == SpanPointer(source_value_id=src.ref.id, start=3, end=5)


@pytest.mark.attack("A3")
def test_extracted_payee_still_needs_the_ledger() -> None:
    src = source()
    result = extract_fields(ScriptedClient([GOOD]), src, FIELDS)
    (payee,) = [v for v in result.values if v.text == ATTACKER_IBAN]
    manifest = sha256_hex("pay_bill")
    contract = IntentContract(
        contract_id="c",
        user_intent="Pay my December bill",
        allowed_tools=(
            ToolScope(
                tool="pay_bill",
                params={"payee": LedgerMarker(kind="ledger", ledger="payees")},
                manifest_hash=manifest,
                effect="irreversible",
            ),
        ),
        budget=EffectBudget(
            max_effects=2,
            max_spend_cents=20000,
            max_egress_bytes=0,
            max_call_amount_cents=20000,
            max_approvals=3,
        ),
        egress_hosts=(),
        authorized_irreversible=("pay_bill",),
    )
    proposal = ToolCallProposal(
        call_id="c2", tool="pay_bill", manifest_hash=manifest, args={"payee": payee.ref}
    )
    store = {src.ref.id: src, payee.ref.id: payee}
    session = SessionState(spent_cents=0, effects_used=0, egress_bytes_used=0, approvals_used=0)
    decision = decide(contract, proposal, store, (), session)
    assert decision.verdict == "BLOCK"
    assert decision.reasons[-1].code == "LEDGER_NOT_FOUND"


@pytest.mark.invariant("I6")
def test_duplicate_field_names_fail_before_any_call() -> None:
    client = ScriptedClient([GOOD])
    twice = [ExtractField(name="payee", unit="iban"), ExtractField(name="payee", unit=None)]
    with pytest.raises(ValueError, match="duplicate field name: payee"):
        extract_fields(client, source(), twice)
    assert client.requests == ()


@pytest.mark.invariant("I6")
def test_no_fields_means_no_call() -> None:
    client = ScriptedClient([])
    result = extract_fields(client, source(), [])
    assert (result.values, result.rejected, result.reasons) == ((), (), ())
    assert client.requests == ()


@pytest.mark.invariant("I6")
def test_extraction_is_deterministic() -> None:
    first = extract_fields(ScriptedClient([GOOD]), source(), FIELDS)
    second = extract_fields(ScriptedClient([GOOD]), source(), FIELDS)
    assert first.model_dump_json() == second.model_dump_json()
    reversed_fields = list(reversed(FIELDS))
    third = extract_fields(ScriptedClient([GOOD]), source(), reversed_fields)
    assert third.model_dump_json() == first.model_dump_json()
