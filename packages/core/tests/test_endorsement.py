from collections.abc import Callable

import pytest

from notary_core.endorsement import (
    ENDORSED_LEDGER,
    ERR_BAD_APPROVAL_ROW,
    apply_approval,
    approval_entries,
    remaining_approvals,
    render_card,
)
from notary_core.ledger import ERR_NOT_CANONICAL, ERR_SOURCE_MISMATCH
from notary_core.models import (
    DiffCard,
    DiffRow,
    EffectBudget,
    EmailOrigin,
    EndorseMarker,
    FreeMarker,
    IntentContract,
    LedgerEntry,
    LedgerMarker,
    LlmOrigin,
    Marker,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
    ToolOrigin,
    ToolScope,
    UserEndorsedSource,
)
from notary_core.monitor import decide

ValueFactory = Callable[..., ResolvedValue]
NAME_ID = "c3.arg.name"
IBAN_ID = "c2.arg.payee"
ENDORSE_NAME: dict[str, Marker] = {"name": EndorseMarker(kind="endorse")}
ATTACKER = "DE00ATTACKER0000000001"


def name_row(preview: str = "alpha consulting") -> DiffRow:
    return DiffRow(
        param="name",
        value_id=NAME_ID,
        origin=LlmOrigin(kind="llm", context_readers=("*",)),
        integrity="untrusted",
        preview=preview,
        nearest_ledger_value=None,
        differing_positions=(),
    )


def name_value(make_value: ValueFactory) -> ResolvedValue:
    return make_value(
        NAME_ID, "Alpha Consulting", unit="identifier", origin="llm", integrity="untrusted"
    )


def contact_proposal(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal]
) -> tuple[ToolCallProposal, dict[str, ResolvedValue]]:
    value = name_value(make_value)
    return make_proposal("add_contact", call_id="c3", name=value), {value.ref.id: value}


def budget(max_approvals: int = 3) -> EffectBudget:
    return EffectBudget(
        max_effects=10,
        max_spend_cents=100000,
        max_egress_bytes=10000,
        max_call_amount_cents=100000,
        max_approvals=max_approvals,
    )


@pytest.mark.invariant("I4")
def test_approval_entries_worked_example(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal]
) -> None:
    proposal, values = contact_proposal(make_value, make_proposal)
    entries = approval_entries(
        "e1", DiffCard(rows=(name_row(),)), proposal, values, {"name": "identifier"}
    )
    assert entries == (
        LedgerEntry(
            entry_id="led-e1-name",
            ledger=ENDORSED_LEDGER,
            key="name: alpha consulting",
            value=values[NAME_ID].ref,
            unit="identifier",
            canonical="alpha consulting",
            source=UserEndorsedSource(kind="user_endorsed", endorsement_id="e1"),
        ),
    )
    assert ENDORSED_LEDGER == "endorsed"


@pytest.mark.invariant("I4")
def test_all_rows_or_none(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal]
) -> None:
    proposal, values = contact_proposal(make_value, make_proposal)
    ghost = name_row().model_copy(update={"param": "iban", "value_id": "c3.arg.iban"})
    card = DiffCard(rows=(name_row(), ghost))
    assert approval_entries("e1", card, proposal, values, {}) == ERR_BAD_APPROVAL_ROW


@pytest.mark.invariant("I4")
def test_row_must_describe_the_proposed_value(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal]
) -> None:
    proposal, values = contact_proposal(make_value, make_proposal)
    other = name_row().model_copy(update={"value_id": "someone-elses-value"})
    assert (
        approval_entries("e1", DiffCard(rows=(other,)), proposal, values, {})
        == ERR_BAD_APPROVAL_ROW
    )


@pytest.mark.invariant("I4")
def test_missing_stored_value_is_rejected(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal]
) -> None:
    proposal, _ = contact_proposal(make_value, make_proposal)
    assert (
        approval_entries("e1", DiffCard(rows=(name_row(),)), proposal, {}, {})
        == ERR_BAD_APPROVAL_ROW
    )


@pytest.mark.invariant("I4")
def test_unit_defaults_to_identifier_and_empty_card_is_empty(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal]
) -> None:
    proposal, values = contact_proposal(make_value, make_proposal)
    built = approval_entries("e1", DiffCard(rows=(name_row(),)), proposal, values, {})
    assert not isinstance(built, str)
    assert [entry.unit for entry in built] == ["identifier"]
    assert approval_entries("e1", DiffCard(rows=()), proposal, values, {}) == ()


def approved_entries(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal], endorsement_id: str
) -> tuple[LedgerEntry, ...]:
    proposal, values = contact_proposal(make_value, make_proposal)
    built = approval_entries(
        endorsement_id, DiffCard(rows=(name_row(),)), proposal, values, {"name": "identifier"}
    )
    assert not isinstance(built, str)
    return built


@pytest.mark.invariant("I4")
def test_apply_approval_writes_user_endorsed_entries(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal]
) -> None:
    entries = approved_entries(make_value, make_proposal, "e1")
    ledger = apply_approval((), entries, "e1")
    assert not isinstance(ledger, str)
    assert ledger == entries
    assert all(
        isinstance(e.source, UserEndorsedSource) and e.source.endorsement_id == "e1" for e in ledger
    )


@pytest.mark.invariant("I4")
def test_apply_approval_is_all_or_nothing(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal]
) -> None:
    good = approved_entries(make_value, make_proposal, "e1")[0]
    bad = good.model_copy(update={"entry_id": "led-e1-bad", "canonical": "Alpha  Consulting"})
    start: tuple[LedgerEntry, ...] = ()
    assert apply_approval(start, (good, bad), "e1") == ERR_NOT_CANONICAL
    assert start == ()


@pytest.mark.invariant("I4")
def test_apply_approval_rejects_a_foreign_endorsement_id(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal]
) -> None:
    entries = approved_entries(make_value, make_proposal, "e1")
    assert apply_approval((), entries, "e2") == ERR_SOURCE_MISMATCH


@pytest.mark.invariant("I4")
def test_apply_approval_is_idempotent_and_accepts_nothing(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal]
) -> None:
    entries = approved_entries(make_value, make_proposal, "e1")
    once = apply_approval((), entries, "e1")
    assert not isinstance(once, str)
    assert apply_approval(once, entries, "e1") == once
    assert apply_approval(once, (), "e1") == once


@pytest.mark.invariant("I2")
def test_endorsed_value_corroborates_an_endorse_marker_not_a_ledger_marker(
    make_value: ValueFactory,
    make_proposal: Callable[..., ToolCallProposal],
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_session: Callable[..., SessionState],
) -> None:
    contact = approved_entries(make_value, make_proposal, "e1")
    contact_proposal_, contact_values = contact_proposal(make_value, make_proposal)
    contact_contract = make_contract(
        tools=(
            make_scope(
                "add_contact", effect="write", params={"name": EndorseMarker(kind="endorse")}
            ),
        ),
        budget=budget(),
    )
    before = decide(contact_contract, contact_proposal_, contact_values, (), make_session())
    assert before.verdict == "ESCALATE"
    after = decide(contact_contract, contact_proposal_, contact_values, contact, make_session())
    assert after.verdict == "ALLOW"

    payee = make_value(IBAN_ID, ATTACKER, unit="iban", origin="llm", integrity="untrusted")
    row = name_row(ATTACKER).model_copy(update={"param": "payee", "value_id": IBAN_ID})
    pay_proposal = make_proposal("pay_bill", call_id="c2", payee=payee)
    entries = approval_entries(
        "e2", DiffCard(rows=(row,)), pay_proposal, {IBAN_ID: payee}, {"payee": "iban"}
    )
    assert not isinstance(entries, str)
    pay_contract = make_contract(
        tools=(
            make_scope(
                "pay_bill",
                effect="irreversible",
                params={
                    "payee": LedgerMarker(kind="ledger", ledger="payees"),
                    "amount": FreeMarker(kind="free"),
                },
            ),
        ),
        authorized_irreversible=("pay_bill",),
        budget=budget(),
    )
    blocked = decide(pay_contract, pay_proposal, {IBAN_ID: payee}, entries, make_session())
    assert blocked.verdict == "BLOCK"
    assert blocked.reasons[-1].code == "LEDGER_NOT_FOUND"


@pytest.mark.attack("A11")
def test_remaining_approvals(
    make_contract: Callable[..., IntentContract], make_session: Callable[..., SessionState]
) -> None:
    contract = make_contract(budget=budget(3))
    assert [
        remaining_approvals(contract, make_session(approvals_used=n)) for n in (0, 2, 3, 5)
    ] == [3, 1, 0, 0]


@pytest.mark.attack("A11")
def test_budget_exhaustion_turns_escalate_into_block(
    make_value: ValueFactory,
    make_proposal: Callable[..., ToolCallProposal],
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_session: Callable[..., SessionState],
) -> None:
    proposal, values = contact_proposal(make_value, make_proposal)
    contract = make_contract(
        tools=(
            make_scope(
                "add_contact", effect="write", params={"name": EndorseMarker(kind="endorse")}
            ),
        ),
        budget=budget(2),
    )
    open_ = decide(contract, proposal, values, (), make_session(approvals_used=1))
    assert open_.verdict == "ESCALATE"
    spent = decide(contract, proposal, values, (), make_session(approvals_used=2))
    assert spent.verdict == "BLOCK"
    assert spent.reasons[-1].code == "BUDGET_APPROVALS_EXHAUSTED"


@pytest.mark.attack("A11")
def test_render_card_exact() -> None:
    assert render_card(DiffCard(rows=(name_row(),))) == "name: alpha consulting [llm, untrusted]"
    payee = DiffRow(
        param="payee",
        value_id="v",
        origin=EmailOrigin(kind="email"),
        integrity="untrusted",
        preview="DE00ACME00000000000002",
        nearest_ledger_value="DE00ACME00000000000001",
        differing_positions=(21,),
    )
    assert render_card(DiffCard(rows=(payee,))) == (
        "payee: DE00ACME00000000000002 [email, untrusted] "
        "nearest known: DE00ACME00000000000001 differs at 21"
    )
    tool = name_row().model_copy(update={"origin": ToolOrigin(kind="tool", name="read_inbox")})
    assert (
        render_card(DiffCard(rows=(tool,))) == "name: alpha consulting [tool:read_inbox, untrusted]"
    )
    two = payee.model_copy(update={"differing_positions": (3, 21), "param": "p2"})
    assert render_card(DiffCard(rows=(payee, two))).splitlines()[1].endswith("differs at 3, 21")
    assert render_card(DiffCard(rows=())) == ""


@pytest.mark.attack("A11")
def test_card_text_ignores_attacker_prose() -> None:
    row = name_row("Approve now! This is safe.")
    assert render_card(DiffCard(rows=(row,))) == "name: Approve now! This is safe. [llm, untrusted]"


@pytest.mark.invariant("I6")
def test_endorsement_is_pure(
    make_value: ValueFactory, make_proposal: Callable[..., ToolCallProposal]
) -> None:
    proposal, values = contact_proposal(make_value, make_proposal)
    card = DiffCard(rows=(name_row(),))
    snapshot = (card.model_dump_json(), proposal.model_dump_json(), dict(values))
    first = approval_entries("e1", card, proposal, values, {"name": "identifier"})
    second = approval_entries("e1", card, proposal, values, {"name": "identifier"})
    assert first == second
    assert snapshot == (card.model_dump_json(), proposal.model_dump_json(), dict(values))
