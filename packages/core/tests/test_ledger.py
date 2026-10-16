import hashlib
import re
from typing import cast, get_args

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import TypeAdapter, ValidationError

from notary_core.ledger import (
    Ledger,
    LedgerClosureError,
    LlmAuthority,
    ToolResultAuthority,
    UserAuthoredAuthority,
    UserEndorsedAuthority,
    WriteAuthority,
    entries_for,
    find_exact,
    with_entry,
)
from notary_core.models import (
    DecisionUnit,
    Label,
    LedgerEntry,
    LedgerSource,
    UserAuthoredSource,
    UserEndorsedSource,
    UserOrigin,
    ValueRef,
)
from notary_core.units import canonicalize

IBAN = "DE89370400440532013000"
EMAIL = "alice@example.com"
HOST = "example.com"
IDENT = "acme utilities"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _entry(
    unit: DecisionUnit,
    canonical: str,
    *,
    entry_id: str = "e1",
    ledger: str = "payees",
    source: LedgerSource | None = None,
) -> LedgerEntry:
    label = Label(
        origin=UserOrigin(kind="user"), integrity="trusted", readers=("*",), span_pointer=None
    )
    return LedgerEntry(
        entry_id=entry_id,
        ledger=ledger,
        key="Acme",
        value=ValueRef(id=f"v-{entry_id}", label=label, content_hash=_sha(canonical)),
        unit=unit,
        canonical=canonical,
        source=source or UserAuthoredSource(kind="user_authored"),
    )


@pytest.mark.attack("A3")
def test_find_exact_matches_canonical_only() -> None:
    entry = _entry("iban", IBAN)
    ledger = (entry,)
    assert find_exact(ledger, "iban", IBAN) == entry
    assert find_exact(ledger, "iban", "DE89 3704 0044 0532 0130 00") is None
    assert find_exact(ledger, "iban", "DE89370400440532013001") is None


@pytest.mark.attack("A3")
def test_entries_for_filters_by_unit_and_name() -> None:
    a = _entry("iban", IBAN, entry_id="e1", ledger="payees")
    b = _entry("email", EMAIL, entry_id="e2", ledger="payees")
    c = _entry("iban", "GB82WEST12345698765432", entry_id="e3", ledger="contacts")
    d = _entry("iban", "DE00ACME00000000000001", entry_id="e4", ledger="payees")
    ledger = [a, b, c, d]
    assert entries_for(ledger, "iban") == (a, c, d)
    assert entries_for(ledger, "iban", "payees") == (a, d)
    assert entries_for(ledger, "email", "contacts") == ()
    assert entries_for(ledger, "email") == (b,)


@pytest.mark.attack("A8")
def test_find_exact_does_not_fold_lookalikes() -> None:
    ledger = (_entry("url_host", "paypal.com"),)
    assert find_exact(ledger, "url_host", "paypal.com") is not None
    assert find_exact(ledger, "url_host", "paypa1.com") is None


AUTHORED = UserAuthoredAuthority(kind="user_authored")
ENDORSED_SRC = UserEndorsedSource(kind="user_endorsed", endorsement_id="t1")
TOOL = ToolResultAuthority(kind="tool_result", tool="read_email")
LLM = LlmAuthority(kind="llm")

MSG_AUTHORITY = "ledger writes require user authority"
MSG_SOURCE = "entry source does not match write authority"
MSG_CANONICAL = "entry is not in canonical form"
MSG_ENTRY_ID = "entry_id already used"

_CURATED: tuple[tuple[DecisionUnit, str], ...] = (
    ("iban", IBAN),
    ("iban", "DE00ACME00000000000001"),
    ("email", EMAIL),
    ("email", "attacker@evil.com"),
    ("url_host", HOST),
    ("identifier", IDENT),
)
_ENDORSEMENT_IDS = ("", "t1", "t2")
_ENTRY_IDS = ("e1", "e2", "e3", "e4")
_LEDGER_NAMES = ("payees", "contacts")


def _raises(message: str) -> pytest.RaisesExc[LedgerClosureError]:
    return pytest.raises(LedgerClosureError, match=f"^{re.escape(message)}$")


def _endorsed(endorsement_id: str) -> UserEndorsedAuthority:
    return UserEndorsedAuthority(kind="user_endorsed", endorsement_id=endorsement_id)


@pytest.mark.invariant("I4")
def test_tool_result_authority_is_rejected() -> None:
    with _raises(MSG_AUTHORITY):
        with_entry((), _entry("email", EMAIL), TOOL)


@pytest.mark.invariant("I4")
def test_llm_authority_is_rejected() -> None:
    with _raises(MSG_AUTHORITY):
        with_entry((), _entry("email", EMAIL), LLM)


@pytest.mark.attack("A9")
def test_attacker_contact_cannot_be_saved_by_tool_result() -> None:
    entry = _entry("email", "attacker@evil.com", source=UserAuthoredSource(kind="user_authored"))
    ledger: Ledger = (_entry("email", EMAIL, entry_id="e2"),)
    with _raises(MSG_AUTHORITY):
        with_entry(ledger, entry, TOOL)
    assert find_exact(ledger, "email", "attacker@evil.com") is None
    assert len(ledger) == 1


@pytest.mark.invariant("I4")
def test_user_authored_write_accepted() -> None:
    entry = _entry("email", EMAIL)
    result = with_entry((), entry, AUTHORED)
    assert isinstance(result, tuple)
    assert entry in result


@pytest.mark.invariant("I4")
def test_user_endorsed_write_accepted_with_matching_endorsement_id() -> None:
    entry = _entry("email", EMAIL, source=ENDORSED_SRC)
    assert with_entry((), entry, _endorsed("t1")) == (entry,)


@pytest.mark.invariant("I4")
def test_endorsed_write_with_mismatched_endorsement_id_rejected() -> None:
    entry = _entry("email", EMAIL, source=ENDORSED_SRC)
    with _raises(MSG_SOURCE):
        with_entry((), entry, _endorsed("t2"))


@pytest.mark.invariant("I4")
def test_source_must_match_authority() -> None:
    with _raises(MSG_SOURCE):
        with_entry((), _entry("email", EMAIL, source=ENDORSED_SRC), AUTHORED)
    with _raises(MSG_SOURCE):
        with_entry((), _entry("email", EMAIL), _endorsed("t1"))


@pytest.mark.invariant("I4")
def test_non_canonical_entry_rejected() -> None:
    with _raises(MSG_CANONICAL):
        with_entry((), _entry("iban", " de89 3704 0044 0532 0130 00"), AUTHORED)


@pytest.mark.invariant("I4")
def test_duplicate_canonical_is_idempotent() -> None:
    entry = _entry("iban", IBAN)
    once = with_entry((), entry, AUTHORED)
    twice = with_entry(once, entry, AUTHORED)
    assert twice == once
    assert len(twice) == 1


@pytest.mark.invariant("I4")
def test_entry_id_reuse_with_different_content_rejected() -> None:
    ledger = (_entry("iban", IBAN, entry_id="e1"),)
    with _raises(MSG_ENTRY_ID):
        with_entry(ledger, _entry("email", EMAIL, entry_id="e1"), AUTHORED)


@pytest.mark.invariant("I4")
def test_original_ledger_not_mutated() -> None:
    ledger = (_entry("iban", IBAN, entry_id="e1"),)
    before = tuple(ledger)
    result = with_entry(ledger, _entry("email", EMAIL, entry_id="e2"), AUTHORED)
    assert ledger == before
    assert len(result) == 2


@pytest.mark.invariant("I4")
def test_rule_order_is_fixed() -> None:
    bad = _entry("iban", " de89 3704", entry_id="e1", source=ENDORSED_SRC)
    with _raises(MSG_AUTHORITY):
        with_entry((), bad, TOOL)
    with _raises(MSG_SOURCE):
        with_entry((), bad, AUTHORED)
    existing = (_entry("email", EMAIL, entry_id="e1"),)
    with _raises(MSG_CANONICAL):
        with_entry(existing, _entry("iban", " de89 3704", entry_id="e1"), AUTHORED)
    with _raises(MSG_ENTRY_ID):
        with_entry(existing, _entry("iban", IBAN, entry_id="e1"), AUTHORED)


@pytest.mark.invariant("I4")
def test_error_messages_are_constants() -> None:
    secret = "ATTACKER@evil.com"
    existing = (_entry("email", EMAIL, entry_id="e1"),)
    cases: list[tuple[str, Ledger, LedgerEntry, WriteAuthority]] = [
        (MSG_AUTHORITY, (), _entry("email", secret), TOOL),
        (MSG_SOURCE, (), _entry("email", secret, source=ENDORSED_SRC), AUTHORED),
        (MSG_CANONICAL, (), _entry("email", secret), AUTHORED),
        (MSG_ENTRY_ID, existing, _entry("email", "attacker@evil.com", entry_id="e1"), AUTHORED),
    ]
    for message, ledger, entry, authority in cases:
        with pytest.raises(LedgerClosureError) as excinfo:
            with_entry(ledger, entry, authority)
        assert str(excinfo.value) == message
        assert secret not in str(excinfo.value)
        assert "evil.com" not in str(excinfo.value)


@pytest.mark.invariant("I4")
def test_unknown_authority_object_fails_closed() -> None:
    ledger = (_entry("email", EMAIL, entry_id="e2"),)
    with _raises(MSG_AUTHORITY):
        with_entry(ledger, _entry("email", "bob@example.com"), cast("WriteAuthority", object()))
    assert len(ledger) == 1


@pytest.mark.invariant("I4")
def test_empty_endorsement_id_rejected() -> None:
    empty_src = UserEndorsedSource(kind="user_endorsed", endorsement_id="")
    with _raises(MSG_SOURCE):
        with_entry((), _entry("email", EMAIL, source=empty_src), _endorsed(""))
    with _raises(MSG_SOURCE):
        with_entry((), _entry("email", EMAIL, source=ENDORSED_SRC), _endorsed(""))
    with _raises(MSG_SOURCE):
        with_entry((), _entry("email", EMAIL, source=empty_src), _endorsed("t1"))


@pytest.mark.invariant("I4")
def test_tool_result_write_of_existing_entry_still_rejected() -> None:
    entry = _entry("email", EMAIL)
    with _raises(MSG_AUTHORITY):
        with_entry((entry,), entry, TOOL)
    with _raises(MSG_AUTHORITY):
        with_entry((entry,), entry, LLM)


@pytest.mark.attack("A3")
def test_duplicate_is_noop_even_with_different_entry_id() -> None:
    first = _entry("email", EMAIL, entry_id="e1")
    ledger = (first,)
    result = with_entry(ledger, _entry("email", EMAIL, entry_id="e2"), AUTHORED)
    assert result == ledger


@pytest.mark.attack("A3")
def test_same_canonical_in_other_unit_or_ledger_is_not_duplicate() -> None:
    first = _entry("url_host", HOST, entry_id="e1")
    other_unit = _entry("identifier", HOST, entry_id="e2")
    other_ledger = _entry("url_host", HOST, entry_id="e3", ledger="contacts")
    result = with_entry(with_entry((first,), other_unit, AUTHORED), other_ledger, AUTHORED)
    assert result == (first, other_unit, other_ledger)


@pytest.mark.attack("A3")
def test_invalid_but_canonical_value_is_accepted() -> None:
    fake = "DE00ACME00000000000001"
    result = with_entry((), _entry("iban", fake), AUTHORED)
    assert find_exact(result, "iban", fake) is not None


@pytest.mark.attack("A3")
@pytest.mark.attack("A7")
def test_accepted_entries_are_findable_after_canonicalization() -> None:
    zero_width = chr(0x200B)
    pairs: tuple[tuple[DecisionUnit, str], ...] = (
        ("iban", f"DE89{zero_width}3704 0044 0532 0130 00"),
        ("email", "Alice <Alice@Example.com>"),
        ("url_host", "https://Example.com/path"),
        ("amount", "1,200.50"),
        ("identifier", "  Acme   Utilities"),
    )
    ledger: Ledger = ()
    for i, (unit, raw) in enumerate(pairs):
        canonical = canonicalize(unit, raw).value
        ledger = with_entry(ledger, _entry(unit, canonical, entry_id=f"e{i}"), AUTHORED)
        found = find_exact(ledger, unit, canonicalize(unit, raw).value)
        assert found is not None
        assert found.canonical == canonical
    assert len(ledger) == len(pairs)


@pytest.mark.invariant("I4")
def test_authority_models_are_strict_and_discriminated() -> None:
    adapter: TypeAdapter[WriteAuthority] = TypeAdapter(WriteAuthority)
    assert isinstance(adapter.validate_json('{"kind":"user_authored"}'), UserAuthoredAuthority)
    endorsed = adapter.validate_json('{"kind":"user_endorsed","endorsement_id":"t1"}')
    assert isinstance(endorsed, UserEndorsedAuthority)
    assert isinstance(
        adapter.validate_json('{"kind":"tool_result","tool":"x"}'), ToolResultAuthority
    )
    assert isinstance(adapter.validate_json('{"kind":"llm"}'), LlmAuthority)
    for bad in (
        '{"kind":"admin"}',
        '{"kind":"llm","extra":1}',
        '{"kind":"user_endorsed"}',
        '{"kind":"tool_result"}',
        "{}",
    ):
        with pytest.raises(ValidationError):
            adapter.validate_json(bad)
    with pytest.raises(ValidationError):
        UserEndorsedAuthority.model_validate_json("{}")
    with pytest.raises(ValidationError):
        endorsed.endorsement_id = "t2"


@pytest.mark.invariant("I4")
def test_append_returns_new_tuple_and_accepts_list_input() -> None:
    first = _entry("iban", IBAN, entry_id="e1")
    second = _entry("email", EMAIL, entry_id="e2")
    ledger = [first]
    result = with_entry(ledger, second, AUTHORED)
    assert ledger == [first]
    assert isinstance(result, tuple)
    assert result == (first, second)
    assert result is not ledger


@pytest.mark.invariant("I6")
def test_with_entry_is_deterministic() -> None:
    ledger = (_entry("iban", IBAN, entry_id="e1"),)
    entry = _entry("email", EMAIL, entry_id="e2", source=ENDORSED_SRC)
    one = with_entry(ledger, entry, _endorsed("t1"))
    two = with_entry(ledger, entry, _endorsed("t1"))
    assert [e.model_dump_json() for e in one] == [e.model_dump_json() for e in two]


def _operation_parts(
    draw: st.DrawFn, unit: DecisionUnit, canonical: str
) -> tuple[LedgerEntry, WriteAuthority]:
    source: LedgerSource
    if draw(st.booleans()):
        source = UserAuthoredSource(kind="user_authored")
    else:
        source = UserEndorsedSource(
            kind="user_endorsed", endorsement_id=draw(st.sampled_from(_ENDORSEMENT_IDS))
        )
    authority: WriteAuthority
    choice = draw(st.sampled_from(("authored", "endorsed", "tool", "llm", "unknown")))
    if choice == "authored":
        authority = AUTHORED
    elif choice == "endorsed":
        authority = _endorsed(draw(st.sampled_from(_ENDORSEMENT_IDS)))
    elif choice == "tool":
        authority = TOOL
    elif choice == "llm":
        authority = LLM
    else:
        authority = cast("WriteAuthority", object())
    entry = _entry(
        unit,
        canonical,
        entry_id=draw(st.sampled_from(_ENTRY_IDS)),
        ledger=draw(st.sampled_from(_LEDGER_NAMES)),
        source=source,
    )
    return entry, authority


@st.composite
def _operation(draw: st.DrawFn) -> tuple[LedgerEntry, WriteAuthority]:
    unit, canonical = draw(st.sampled_from(_CURATED))
    return _operation_parts(draw, unit, canonical)


@st.composite
def _free_operation(draw: st.DrawFn) -> tuple[LedgerEntry, WriteAuthority]:
    unit = draw(st.sampled_from(get_args(DecisionUnit)))
    canonical = draw(st.one_of(st.sampled_from([c for _, c in _CURATED]), st.text()))
    return _operation_parts(draw, unit, canonical)


def _is_user_authority(authority: WriteAuthority) -> bool:
    return isinstance(authority, UserAuthoredAuthority | UserEndorsedAuthority)


@pytest.mark.invariant("I4")
@given(st.lists(_operation(), max_size=12))
def test_ledger_is_append_only_property(
    operations: list[tuple[LedgerEntry, WriteAuthority]],
) -> None:
    ledger: Ledger = ()
    for entry, authority in operations:
        try:
            new = with_entry(ledger, entry, authority)
        except LedgerClosureError:
            continue
        assert _is_user_authority(authority)
        assert new[: len(ledger)] == ledger
        assert len(new) - len(ledger) in (0, 1)
        triples = [(e.ledger, e.unit, e.canonical) for e in new]
        assert len(set(triples)) == len(triples)
        ids = [e.entry_id for e in new]
        assert len(set(ids)) == len(ids)
        assert all(canonicalize(e.unit, e.canonical).value == e.canonical for e in new)
        ledger = new


@pytest.mark.invariant("I4")
@given(_free_operation())
def test_with_entry_only_raises_closure_error(
    operation: tuple[LedgerEntry, WriteAuthority],
) -> None:
    entry, authority = operation
    try:
        result = with_entry((), entry, authority)
    except LedgerClosureError:
        return
    assert isinstance(result, tuple)
