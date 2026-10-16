import pytest

from notary_world.cast import (
    ACCOUNTANT_EMAIL,
    ATTACKER_IBAN,
    BILL_MAIL_ID,
    BILLER_IBAN,
    SECRET_2FA_CODE,
    USER_EMAIL,
    USER_IBAN,
    WORLD_NOW,
)
from notary_world.state import (
    CalendarEvent,
    ContactEntry,
    SentMail,
    SlackMessage,
    Transfer,
    WorldState,
    diff,
    seed_world,
    snapshot,
)
from notary_world.tools import EffectRecord, WorldToolResult, call


def ok(state: WorldState, tool: str, args: dict[str, str]) -> WorldToolResult:
    result = call(state, tool, args)
    assert result.error is None, result.error
    return result


def record_ids(result: WorldToolResult) -> list[str]:
    return [r.record_id for r in result.records]


@pytest.mark.attack("A1")
def test_read_inbox_lists_non_deleted_mails_with_external_fields():
    state = seed_world()
    result = ok(state, "read_inbox", {})
    assert record_ids(result) == ["m-oct", BILL_MAIL_ID]
    dec = result.records[1]
    assert [f.name for f in dec.fields] == ["sender", "subject", "body", "verified", "attachment_0"]
    assert dec.external_fields == ("sender", "subject", "body", "attachment_0")
    assert dec.platform_fields == ("verified",)
    assert dec.readers == ("*",)
    assert all(f.unit is None for f in dec.fields)
    assert result.new_state == state
    assert result.effect is not None
    assert result.effect.summary == "read 2 messages"
    assert result.effect.changed is False


@pytest.mark.invariant("I1")
def test_read_inbox_skips_deleted_mail():
    state = ok(seed_world(), "delete_email", {"message_id": "m-oct"}).new_state
    result = ok(state, "read_inbox", {})
    assert record_ids(result) == [BILL_MAIL_ID]
    assert result.effect is not None
    assert result.effect.summary == "read 1 messages"


@pytest.mark.invariant("I1")
def test_read_email_and_not_found():
    state = seed_world()
    assert record_ids(ok(state, "read_email", {"message_id": BILL_MAIL_ID})) == [BILL_MAIL_ID]
    missing = call(state, "read_email", {"message_id": "nope"})
    assert missing.error == "not_found"
    assert missing.new_state is state
    deleted = ok(state, "delete_email", {"message_id": "m-oct"}).new_state
    assert call(deleted, "read_email", {"message_id": "m-oct"}).error == "not_found"


@pytest.mark.invariant("I3")
def test_list_files_prefix_and_readers():
    state = seed_world()
    secrets = ok(state, "list_files", {"path": "secrets/"})
    assert len(secrets.records) == 2
    assert all(r.readers == ("user",) for r in secrets.records)
    everything = ok(state, "list_files", {"path": ""})
    assert record_ids(everything) == sorted(record_ids(everything))
    assert len(everything.records) == 4
    todo = next(r for r in everything.records if r.record_id == "notes/todo.txt")
    assert todo.readers == ("*",)
    assert ok(state, "list_files", {}).records == everything.records


@pytest.mark.invariant("I3")
def test_read_file_secret_has_user_readers():
    state = seed_world()
    result = ok(state, "read_file", {"path": "secrets/2fa.txt"})
    (record,) = result.records
    assert record.readers == ("user",)
    assert [(f.name, f.text) for f in record.fields] == [("text", SECRET_2FA_CODE)]
    assert record.external_fields == ("text",)
    assert call(state, "read_file", {"path": "nope.txt"}).error == "not_found"


@pytest.mark.attack("A6")
def test_read_calendar_marks_description_external():
    result = ok(seed_world(), "read_calendar", {})
    assert len(result.records) == 2
    for record in result.records:
        assert record.external_fields == ("title", "description")
        attendees = next(f for f in record.fields if f.name == "attendees")
        assert attendees.text == USER_EMAIL


@pytest.mark.attack("A6")
def test_read_slack_channel():
    state = seed_world()
    for channel in ("finance", "general"):
        result = ok(state, "read_slack", {"channel": channel})
        assert len(result.records) == 1
        assert result.records[0].external_fields == ("author", "text")
    assert call(state, "read_slack", {"channel": "nope"}).error == "not_found"


@pytest.mark.invariant("I3")
def test_get_balance_is_user_only():
    result = ok(seed_world(), "get_balance", {})
    (record,) = result.records
    assert record.record_id == f"acct-{USER_IBAN}"
    assert record.readers == ("user",)
    fields = {f.name: f for f in record.fields}
    assert fields["balance"].text == "2500.00"
    assert fields["balance"].unit == "amount"
    assert fields["iban"].unit == "iban"
    assert record.platform_fields == ("iban", "balance")
    assert record.external_fields == ()


@pytest.mark.attack("A5")
def test_send_email_appends_sent_mail_and_counts_egress():
    state = seed_world()
    result = ok(state, "send_email", {"to": ACCOUNTANT_EMAIL, "subject": "Hi", "body": "Bye"})
    assert result.new_state.sent_mails == (
        SentMail(sent_id="o1", to=ACCOUNTANT_EMAIL, cc="", subject="Hi", body="Bye"),
    )
    assert result.effect == EffectRecord(
        tool="send_email",
        effect="write",
        summary=f"sent email to {ACCOUNTANT_EMAIL}",
        spent_cents=0,
        egress_bytes=5,
        changed=True,
    )


@pytest.mark.attack("A5")
def test_post_slack_and_create_event():
    state = seed_world()
    posted = ok(state, "post_slack", {"channel": "general", "text": "hello"})
    assert posted.new_state.slack_messages[-1] == SlackMessage(
        message_id="s3", channel="general", author="user", text="hello"
    )
    assert posted.effect is not None
    assert posted.effect.egress_bytes == len("hello")
    assert posted.effect.summary == "posted to general"

    created = ok(state, "create_event", {"attendees": USER_EMAIL, "title": "Lunch"})
    assert created.new_state.events[-1] == CalendarEvent(
        event_id="ev3",
        title="Lunch",
        description="",
        start=WORLD_NOW,
        end=WORLD_NOW,
        attendees=(USER_EMAIL,),
    )
    assert created.effect is not None
    assert created.effect.egress_bytes == len("Lunch")
    assert created.effect.summary == "created event Lunch"


@pytest.mark.attack("A9")
def test_add_contact_appends_contact():
    result = ok(seed_world(), "add_contact", {"name": "Eve"})
    assert result.new_state.contacts[-1] == ContactEntry(
        contact_id="c3", name="Eve", email="", iban=""
    )
    assert result.effect is not None
    assert result.effect.summary == "added contact Eve"
    assert result.effect.egress_bytes == 0


@pytest.mark.attack("A3")
def test_pay_bill_debits_and_records_transfer():
    result = ok(seed_world(), "pay_bill", {"payee": BILLER_IBAN, "amount": "120.00"})
    assert result.new_state.bank.accounts[0].balance_cents == 238000
    assert result.new_state.bank.transfers[-1] == Transfer(
        transfer_id="t1",
        from_iban=USER_IBAN,
        to_iban=BILLER_IBAN,
        amount_cents=12000,
        reference="",
        via="pay_bill",
    )
    assert result.effect == EffectRecord(
        tool="pay_bill",
        effect="irreversible",
        summary=f"paid 120.00 EUR to {BILLER_IBAN}",
        spent_cents=12000,
        egress_bytes=0,
        changed=True,
    )


@pytest.mark.attack("A4")
def test_send_money_uses_its_own_summary():
    result = ok(seed_world(), "send_money", {"payee": ATTACKER_IBAN, "amount": "500"})
    assert result.effect is not None
    assert result.effect.summary == f"sent 500.00 EUR to {ATTACKER_IBAN}"
    assert result.effect.effect == "irreversible"
    assert result.new_state.bank.transfers[-1].via == "send_money"


@pytest.mark.attack("A3")
@pytest.mark.parametrize(
    ("amount", "code"),
    [("abc", "invalid_amount"), ("0", "invalid_amount"), ("9999999", "insufficient_funds")],
)
def test_payment_errors(amount: str, code: str):
    state = seed_world()
    result = call(state, "pay_bill", {"payee": BILLER_IBAN, "amount": amount})
    assert result.error == code
    assert result.new_state is state
    assert result.effect is None
    assert result.records == ()


@pytest.mark.attack("A4")
def test_delete_email_marks_deleted():
    state = seed_world()
    result = ok(state, "delete_email", {"message_id": "m-oct"})
    deleted = next(m for m in result.new_state.mails if m.mail_id == "m-oct")
    assert deleted.deleted is True
    assert result.effect is not None
    assert result.effect.summary == "deleted email m-oct"
    assert result.effect.effect == "irreversible"
    again = call(result.new_state, "delete_email", {"message_id": "m-oct"})
    assert again.error == "not_found"
    assert call(state, "delete_email", {"message_id": "nope"}).error == "not_found"


WRITE_CALLS: list[tuple[str, dict[str, str]]] = [
    ("send_email", {"to": ACCOUNTANT_EMAIL, "subject": "s", "body": "b"}),
    ("post_slack", {"channel": "general", "text": "t"}),
    ("create_event", {"attendees": USER_EMAIL, "title": "x"}),
    ("add_contact", {"name": "Eve"}),
    ("pay_bill", {"payee": BILLER_IBAN, "amount": "1"}),
    ("send_money", {"payee": BILLER_IBAN, "amount": "1"}),
    ("delete_email", {"message_id": "m-oct"}),
]


@pytest.mark.invariant("I6")
@pytest.mark.parametrize(("tool", "args"), WRITE_CALLS)
def test_write_tools_do_not_mutate_the_input_state(tool: str, args: dict[str, str]):
    state = seed_world()
    before = snapshot(state)
    result = ok(state, tool, args)
    assert snapshot(state) == before
    assert result.new_state is not state
    assert result.effect is not None
    assert result.effect.changed is True


@pytest.mark.invariant("I1")
def test_effects_show_up_in_the_world_diff():
    state = seed_world()
    result = ok(state, "pay_bill", {"payee": BILLER_IBAN, "amount": "120.00"})
    changes = diff(state, result.new_state).changes
    assert [(c.entity, c.key, c.kind) for c in changes] == [
        ("account", USER_IBAN, "changed"),
        ("transfer", "t1", "added"),
    ]
