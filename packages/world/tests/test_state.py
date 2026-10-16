from collections.abc import Callable
from dataclasses import dataclass

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from notary_core.canon import canonical_json
from notary_world.cast import (
    ATTACKER_EMAIL,
    ATTACKER_HOST,
    ATTACKER_IBAN,
    BILL_AMOUNT,
    BILLER_IBAN,
    LOOKALIKE_BILLER_IBAN,
    USER_IBAN,
    USER_NAME,
)
from notary_world.state import (
    ENTITY_ORDER,
    BankAccount,
    BankBook,
    CalendarEvent,
    ContactEntry,
    EntityKind,
    FileEntry,
    MailMessage,
    Payee,
    SentMail,
    SlackMessage,
    ToolDescription,
    Transfer,
    WorldChange,
    WorldDiff,
    WorldState,
    diff,
    reset,
    seed_world,
    snapshot,
    state_hash,
)

OTHER_IBAN = "DE00OTHER0000000000001"
"""A test-local account number that is not part of the cast."""


def _bank(state: WorldState, **updates: tuple[object, ...]) -> WorldState:
    return state.model_copy(update={"bank": state.bank.model_copy(update=updates)})


def _with_sent_mail(state: WorldState) -> WorldState:
    mail = SentMail(sent_id="o1", to=ATTACKER_EMAIL, cc="", subject="s", body="b")
    return state.model_copy(update={"sent_mails": (mail,)})


def _with_tool_description(state: WorldState) -> WorldState:
    entry = ToolDescription(tool="pay_bill", description="d")
    return state.model_copy(update={"tool_descriptions": (entry,)})


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("seed", [0, 1, 7, 1337])
def test_same_seed_gives_identical_bytes(seed: int) -> None:
    first = seed_world(seed)
    second = seed_world(seed)
    assert first.model_dump_json() == second.model_dump_json()
    assert snapshot(first) == snapshot(second)
    assert state_hash(first) == state_hash(second)


@pytest.mark.invariant("I6")
def test_seed_zero_is_the_base_world() -> None:
    world = seed_world()
    assert world.seed == 0
    assert world.bank.accounts[0].balance_cents == 250000
    assert [m.mail_id for m in world.mails] == ["m-oct", "m-dec"]
    assert [f.path for f in world.files] == [
        "notes/todo.txt",
        "december.txt",
        "secrets/2fa.txt",
        "secrets/api_keys.txt",
    ]
    assert len(world.slack_messages) == 2


@pytest.mark.invariant("I6")
def test_seed_five_adds_only_noise() -> None:
    base = seed_world()
    world = seed_world(5)
    assert world.bank.accounts[0].balance_cents == 255000
    assert len(world.mails) == 3
    assert world.mails[2].mail_id == "m-n1"
    assert len(world.slack_messages) == 4
    assert world.bank.payees == base.bank.payees
    assert world.bank.transfers == base.bank.transfers
    assert world.contacts == base.contacts
    assert world.files == base.files
    assert world.events == base.events
    assert world.mails[1] == base.mails[1]


@pytest.mark.invariant("I6")
def test_negative_seed_is_rejected() -> None:
    with pytest.raises(ValueError, match="seed must be >= 0"):
        seed_world(-1)


@pytest.mark.invariant("I6")
@given(s=st.integers(0, 60), t=st.integers(0, 60))
def test_noise_only_touches_account_mail_and_slack(s: int, t: int) -> None:
    entities = {change.entity for change in diff(seed_world(s), seed_world(t)).changes}
    assert entities <= {"account", "mail", "slack_message"}


@pytest.mark.attack("A3")
@pytest.mark.parametrize("seed", range(10))
def test_clean_world_contains_no_attacker_strings(seed: int) -> None:
    text = snapshot(seed_world(seed))
    for attacker_string in (ATTACKER_IBAN, ATTACKER_EMAIL, ATTACKER_HOST, LOOKALIKE_BILLER_IBAN):
        assert attacker_string not in text


@pytest.mark.attack("A3")
def test_bill_facts_are_consistent() -> None:
    world = seed_world()
    bill = next(m for m in world.mails if m.mail_id == "m-dec")
    bill_file = next(f for f in world.files if f.path == "december.txt")
    for text in (bill.body, bill.attachments[0].text, bill_file.text):
        assert BILLER_IBAN in text
        assert BILL_AMOUNT in text
    assert world.contacts[0].iban == BILLER_IBAN
    assert world.bank.payees[0].iban == BILLER_IBAN


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("seed", [0, 5])
def test_reset_restores_the_seeded_world(seed: int) -> None:
    mutated = _with_sent_mail(seed_world(seed))
    mutated = _bank(
        mutated,
        accounts=(BankAccount(iban=USER_IBAN, owner=USER_NAME, balance_cents=1),),
    )
    assert reset(mutated) == seed_world(seed)


@pytest.mark.invariant("I6")
def test_reset_does_not_mutate_its_input() -> None:
    mutated = _with_sent_mail(seed_world())
    before = snapshot(mutated)
    reset(mutated)
    assert snapshot(mutated) == before


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("seed", range(6))
def test_diff_identity_is_empty(seed: int) -> None:
    world = seed_world(seed)
    assert diff(world, world) == WorldDiff(changes=())


@dataclass(frozen=True)
class EntityCase:
    entity: EntityKind
    added_key: str
    add: Callable[[WorldState], WorldState]
    removed_key: str
    remove_base: Callable[[WorldState], WorldState]
    remove: Callable[[WorldState], WorldState]
    edit_base: Callable[[WorldState], WorldState]
    edit: Callable[[WorldState], WorldState]


def _identity(state: WorldState) -> WorldState:
    return state


CASES: tuple[EntityCase, ...] = (
    EntityCase(
        "account",
        OTHER_IBAN,
        lambda s: _bank(
            s,
            accounts=(
                *s.bank.accounts,
                BankAccount(iban=OTHER_IBAN, owner="x", balance_cents=1),
            ),
        ),
        USER_IBAN,
        _identity,
        lambda s: _bank(s, accounts=()),
        _identity,
        lambda s: _bank(s, accounts=(s.bank.accounts[0].model_copy(update={"balance_cents": 1}),)),
    ),
    EntityCase(
        "payee",
        "p2",
        lambda s: _bank(s, payees=(*s.bank.payees, Payee(payee_id="p2", name="n", iban="i"))),
        "p1",
        _identity,
        lambda s: _bank(s, payees=()),
        _identity,
        lambda s: _bank(s, payees=(s.bank.payees[0].model_copy(update={"name": "other"}),)),
    ),
    EntityCase(
        "transfer",
        "t1",
        lambda s: _bank(
            s,
            transfers=(
                *s.bank.transfers,
                Transfer(
                    transfer_id="t1",
                    from_iban="a",
                    to_iban="b",
                    amount_cents=1,
                    reference="r",
                    via="pay_bill",
                ),
            ),
        ),
        "t0",
        _identity,
        lambda s: _bank(s, transfers=()),
        _identity,
        lambda s: _bank(
            s, transfers=(s.bank.transfers[0].model_copy(update={"reference": "other"}),)
        ),
    ),
    EntityCase(
        "mail",
        "m-x",
        lambda s: s.model_copy(
            update={
                "mails": (
                    *s.mails,
                    MailMessage(
                        mail_id="m-x",
                        sender="s",
                        subject="s",
                        body="b",
                        attachments=(),
                        verified_sender=False,
                        deleted=False,
                    ),
                )
            }
        ),
        "m-oct",
        _identity,
        lambda s: s.model_copy(update={"mails": s.mails[1:]}),
        _identity,
        lambda s: s.model_copy(
            update={"mails": (s.mails[0].model_copy(update={"deleted": True}), *s.mails[1:])}
        ),
    ),
    EntityCase(
        "sent_mail",
        "o1",
        _with_sent_mail,
        "o1",
        _with_sent_mail,
        lambda s: s.model_copy(update={"sent_mails": ()}),
        _with_sent_mail,
        lambda s: s.model_copy(
            update={"sent_mails": (s.sent_mails[0].model_copy(update={"body": "other"}),)}
        ),
    ),
    EntityCase(
        "contact",
        "c3",
        lambda s: s.model_copy(
            update={
                "contacts": (
                    *s.contacts,
                    ContactEntry(contact_id="c3", name="n", email="e", iban=""),
                )
            }
        ),
        "c2",
        _identity,
        lambda s: s.model_copy(update={"contacts": s.contacts[:1]}),
        _identity,
        lambda s: s.model_copy(
            update={
                "contacts": (s.contacts[0], s.contacts[1].model_copy(update={"email": "other"}))
            }
        ),
    ),
    EntityCase(
        "event",
        "ev3",
        lambda s: s.model_copy(
            update={
                "events": (
                    *s.events,
                    CalendarEvent(
                        event_id="ev3",
                        title="t",
                        description="d",
                        start="s",
                        end="e",
                        attendees=(),
                    ),
                )
            }
        ),
        "ev1",
        _identity,
        lambda s: s.model_copy(update={"events": s.events[1:]}),
        _identity,
        lambda s: s.model_copy(
            update={
                "events": (s.events[0].model_copy(update={"description": "other"}), s.events[1])
            }
        ),
    ),
    EntityCase(
        "slack_message",
        "s3",
        lambda s: s.model_copy(
            update={
                "slack_messages": (
                    *s.slack_messages,
                    SlackMessage(message_id="s3", channel="general", author="a", text="t"),
                )
            }
        ),
        "s1",
        _identity,
        lambda s: s.model_copy(update={"slack_messages": s.slack_messages[1:]}),
        _identity,
        lambda s: s.model_copy(
            update={
                "slack_messages": (
                    s.slack_messages[0].model_copy(update={"text": "other"}),
                    s.slack_messages[1],
                )
            }
        ),
    ),
    EntityCase(
        "file",
        "x.txt",
        lambda s: s.model_copy(
            update={"files": (*s.files, FileEntry(path="x.txt", text="t", secret=False))}
        ),
        "notes/todo.txt",
        _identity,
        lambda s: s.model_copy(update={"files": s.files[1:]}),
        _identity,
        lambda s: s.model_copy(
            update={"files": (s.files[0].model_copy(update={"text": "other"}), *s.files[1:])}
        ),
    ),
    EntityCase(
        "tool_description",
        "pay_bill",
        _with_tool_description,
        "pay_bill",
        _with_tool_description,
        lambda s: s.model_copy(update={"tool_descriptions": ()}),
        _with_tool_description,
        lambda s: s.model_copy(
            update={
                "tool_descriptions": (
                    s.tool_descriptions[0].model_copy(update={"description": "other"}),
                )
            }
        ),
    ),
)


def test_every_entity_kind_has_a_case() -> None:
    assert [case.entity for case in CASES] == list(ENTITY_ORDER)


@pytest.mark.invariant("I1")
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.entity)
def test_diff_added_removed_changed_per_entity(case: EntityCase) -> None:
    base = seed_world()
    added = case.add(base)
    (change,) = diff(base, added).changes
    assert (change.entity, change.key, change.kind) == (case.entity, case.added_key, "added")
    assert change.before is None
    assert change.after is not None

    start = case.remove_base(base)
    (change,) = diff(start, case.remove(start)).changes
    assert (change.entity, change.key, change.kind) == (case.entity, case.removed_key, "removed")
    assert change.before is not None
    assert change.after is None

    start = case.edit_base(base)
    (change,) = diff(start, case.edit(start)).changes
    assert (change.entity, change.kind) == (case.entity, "changed")
    assert change.before is not None
    assert change.after is not None
    assert change.before != change.after


@pytest.mark.invariant("I1")
def test_diff_order_is_canonical() -> None:
    before = seed_world()
    mail = SentMail(sent_id="o1", to=ATTACKER_EMAIL, cc="", subject="s", body="b")
    after = before.model_copy(
        update={
            "sent_mails": (mail,),
            "bank": before.bank.model_copy(
                update={
                    "accounts": (
                        BankAccount(iban=USER_IBAN, owner=USER_NAME, balance_cents=238000),
                    )
                }
            ),
        }
    )
    assert diff(before, after).changes == (
        WorldChange(
            entity="account",
            key=USER_IBAN,
            kind="changed",
            before=canonical_json({"balance_cents": 250000, "iban": USER_IBAN, "owner": USER_NAME}),
            after=canonical_json({"balance_cents": 238000, "iban": USER_IBAN, "owner": USER_NAME}),
        ),
        WorldChange(
            entity="sent_mail",
            key="o1",
            kind="added",
            before=None,
            after=canonical_json(
                {"body": "b", "cc": "", "sent_id": "o1", "subject": "s", "to": ATTACKER_EMAIL}
            ),
        ),
    )


@pytest.mark.invariant("I1")
def test_diff_is_reversible() -> None:
    a = seed_world()
    b = _with_sent_mail(
        _bank(a, accounts=(a.bank.accounts[0].model_copy(update={"balance_cents": 5}),))
    )
    forward = diff(a, b).changes
    backward = diff(b, a).changes
    assert [(c.entity, c.key) for c in forward] == [(c.entity, c.key) for c in backward]
    swapped = {"added": "removed", "removed": "added", "changed": "changed"}
    for f, r in zip(forward, backward, strict=True):
        assert r.kind == swapped[f.kind]
        assert (r.before, r.after) == (f.after, f.before)


@pytest.mark.invariant("I6")
def test_diff_does_not_mutate_inputs() -> None:
    a = seed_world()
    b = _with_sent_mail(a)
    before = (snapshot(a), snapshot(b))
    diff(a, b)
    assert (snapshot(a), snapshot(b)) == before


def _rebuild(
    world: WorldState,
    *,
    bank: BankBook | None = None,
    mails: tuple[MailMessage, ...] | None = None,
) -> WorldState:
    """Validate a copy of `world` with some collections replaced (`model_copy` would not)."""
    return WorldState(
        seed=world.seed,
        now=world.now,
        user_email=world.user_email,
        bank=world.bank if bank is None else bank,
        mails=world.mails if mails is None else mails,
        sent_mails=world.sent_mails,
        contacts=world.contacts,
        events=world.events,
        slack_messages=world.slack_messages,
        files=world.files,
        tool_descriptions=world.tool_descriptions,
    )


@pytest.mark.invariant("I6")
def test_duplicate_keys_are_rejected() -> None:
    world = seed_world()
    payee = world.bank.payees[0]
    duplicated = BankBook(
        accounts=world.bank.accounts, payees=(payee, payee), transfers=world.bank.transfers
    )
    with pytest.raises(ValidationError, match="duplicate payee key: p1"):
        _rebuild(world, bank=duplicated)
    with pytest.raises(ValidationError, match="duplicate mail key: m-oct"):
        _rebuild(world, mails=(world.mails[0], world.mails[0]))


@pytest.mark.invariant("I6")
def test_models_are_frozen() -> None:
    world = seed_world()
    with pytest.raises(ValidationError):
        world.__setattr__("seed", 1)


@pytest.mark.invariant("I6")
def test_models_are_strict_and_forbid_extra() -> None:
    fields: dict[str, object] = {"iban": USER_IBAN, "owner": USER_NAME, "balance_cents": 1}
    assert BankAccount.model_validate(fields).balance_cents == 1
    with pytest.raises(ValidationError):
        BankAccount.model_validate({**fields, "balance_cents": "1"})
    with pytest.raises(ValidationError):
        BankAccount.model_validate({**fields, "extra": 1})
    with pytest.raises(ValidationError):
        BankAccount.model_validate({**fields, "balance_cents": -1})
