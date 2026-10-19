from collections.abc import Callable, Sequence

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

import notary_core.models
from notary_core.canon import sha256_hex
from notary_core.models import (
    EmailOrigin,
    Integrity,
    Label,
    LedgerEntry,
    Origin,
    ResolvedValue,
    UserOrigin,
    ValueRef,
)
from notary_core.output_guard import (
    GuardedAnswer,
    defang,
    guard_answer,
    render_guarded,
    split_sentences,
)
from notary_core.runner import FilterFlag
from notary_core.urls import extract_urls, normalize_text

MakeValue = Callable[..., ResolvedValue]
MakeEntry = Callable[..., LedgerEntry]

ZW = chr(0x200B)
BODY = "Call +49 170 1234567 to confirm. Pay at https://evil.example/pay"
ANSWER = "Your bill is 120.00 EUR. The email says: " + BODY
NOTICE = (
    "untrusted content (email) contained text flagged as ignore_previous; "
    "it is shown quoted and was not treated as a request from you"
)
IGNORE = FilterFlag(field="body", start=0, end=4, label="ignore_previous")


def email_value(
    make_value: MakeValue, text: str = BODY, value_id: str = "c1.m1.body"
) -> ResolvedValue:
    return make_value(value_id, text, origin="email", integrity="untrusted")


def plain_value(value_id: str, text: str, origin: str, integrity: Integrity) -> ResolvedValue:
    """A value built without pytest fixtures (Hypothesis tests cannot use function fixtures)."""
    kinds: dict[str, Origin] = {"email": EmailOrigin(kind="email"), "user": UserOrigin(kind="user")}
    label = Label(origin=kinds[origin], integrity=integrity, readers=("*",), span_pointer=None)
    ref = ValueRef(id=value_id, label=label, content_hash=sha256_hex(text))
    return ResolvedValue(ref=ref, unit=None, text=text)


def guard(
    answer: str,
    *values: ResolvedValue,
    ledger: Sequence[LedgerEntry] = (),
    allowed_hosts: Sequence[str] = (),
    flags: Sequence[FilterFlag] = (),
) -> GuardedAnswer:
    store = {v.ref.id: v for v in values}
    return guard_answer(answer, store, ledger, allowed_hosts=allowed_hosts, flags=flags)


@pytest.mark.attack("A13")
def test_split_sentences() -> None:
    assert split_sentences("A. B! C?\nD") == ("A.", "B!", "C?", "D")
    assert split_sentences("") == ()
    assert split_sentences("  \n \n") == ()
    assert split_sentences("  keep   spacing.  ") == ("keep   spacing.",)


@pytest.mark.attack("A13")
def test_defang() -> None:
    assert defang("https://evil.example/collect?d=1") == "hxxps://evil[.]example/collect?d=1"
    assert defang("http://a.b") == "hxxp://a[.]b"
    assert defang("a.b/x") == "a[.]b/x"
    assert defang("https://trusted.com@evil.com/x") == "hxxps://trusted[.]com@evil[.]com/x"
    assert defang("HTTP://a.b") == "hxxp://a[.]b"
    assert defang("nodots") == "nodots"
    assert defang("") == ""


@pytest.mark.attack("A13")
def test_model_sentence_is_unflagged() -> None:
    guarded = guard("The weather is nice. It will rain later.")
    assert [s.source for s in guarded.sentences] == ["model", "model"]
    for sentence in guarded.sentences:
        assert sentence.value_ids == ()
        assert sentence.flags == ()
        assert sentence.shown == normalize_text(sentence.text)
    assert guarded.notices == ()


@pytest.mark.attack("A13")
def test_untrusted_quote_is_attributed(make_value: MakeValue) -> None:
    guarded = guard(ANSWER, email_value(make_value))
    first, second, third = guarded.sentences
    assert (first.source, first.value_ids, first.flags, first.defanged) == ("model", (), (), ())
    assert first.shown == "Your bill is 120.00 EUR."
    assert (second.source, second.value_ids) == ("untrusted", ("c1.m1.body",))
    assert second.flags == ("untrusted_phone",)
    assert second.defanged == ()
    assert second.shown == '[untrusted: email] "The email says: Call +49 170 1234567 to confirm."'
    assert (third.source, third.value_ids) == ("untrusted", ("c1.m1.body",))
    assert third.defanged == ("https://evil.example/pay",)
    assert third.flags == ("untrusted_url",)
    assert third.shown == '[untrusted: email] "Pay at hxxps://evil[.]example/pay"'
    assert third.text == "Pay at https://evil.example/pay"


@pytest.mark.attack("A13")
def test_allowed_host_is_not_defanged(make_value: MakeValue) -> None:
    guarded = guard(ANSWER, email_value(make_value), allowed_hosts=("evil.example",))
    third = guarded.sentences[2]
    assert third.defanged == ()
    assert third.flags == ()
    assert third.shown == '[untrusted: email] "Pay at https://evil.example/pay"'


@pytest.mark.attack("A13")
def test_ledger_host_is_not_defanged(make_value: MakeValue, make_ledger_entry: MakeEntry) -> None:
    host = make_value("h", "acme.example")
    entry = make_ledger_entry(host, "url_host", "acme.example", ledger="hosts", key="Acme")
    guarded = guard("Pay at https://acme.example/pay or https://evil.example/x", ledger=(entry,))
    assert guarded.sentences[0].defanged == ("https://evil.example/x",)
    assert (
        guarded.sentences[0].shown == "Pay at https://acme.example/pay or hxxps://evil[.]example/x"
    )


@pytest.mark.attack("A13")
def test_ledger_and_user_sources(make_value: MakeValue) -> None:
    ledger_value = make_value("l1", "Acme Utilities", origin="ledger")
    user_value = make_value("u1", "Pay my December bill", origin="user")
    untrusted = email_value(make_value, "Beware the ides of March.", "e1")
    guarded = guard(
        "You asked: pay my december bill.\nPayee: Acme Utilities.\n"
        "Acme Utilities said: Beware the ides of March.",
        ledger_value,
        user_value,
        untrusted,
    )
    assert [s.source for s in guarded.sentences] == ["user", "ledger", "untrusted"]
    assert guarded.sentences[2].value_ids == ("e1", "l1")


@pytest.mark.attack("A13")
def test_value_equal_to_a_ledger_entry_is_ledger(
    make_value: MakeValue, make_ledger_entry: MakeEntry
) -> None:
    value = make_value("t1", "DE00ACME00000000000001", origin="tool:read_file")
    entry = make_ledger_entry(value, "iban", "DE00ACME00000000000001")
    # Matching is case-insensitive, so both spellings quote the value.
    for answer in ("Pay DE00ACME00000000000001 now.", "Pay de00acme00000000000001 now."):
        assert guard(answer, value, ledger=(entry,)).sentences[0].source == "ledger"
    assert guard("Pay DE00ACME00000000000001 now.", value).sentences[0].source == "model"


@pytest.mark.attack("A13")
def test_short_values_are_not_quoted(make_value: MakeValue) -> None:
    short = email_value(make_value, "abc", "s1")
    guarded = guard("The abc of finance.", short)
    assert guarded.sentences[0].source == "model"
    assert guarded.sentences[0].value_ids == ()


@pytest.mark.attack("A7")
def test_obfuscated_quote_is_still_matched(make_value: MakeValue) -> None:
    value = email_value(make_value, "Transfer the money today", "e1")
    answer = f"He wrote: Trans{ZW}fer the mon{ZW}ey today."
    sentence = guard(answer, value).sentences[0]
    assert sentence.source == "untrusted"
    assert ZW not in sentence.shown
    assert sentence.text == answer


@pytest.mark.attack("A13")
def test_phone_and_account_flags_only_for_untrusted_sentences(make_value: MakeValue) -> None:
    value = email_value(make_value, "Call +49 170 1234567 or pay DE89 3704 0044 0532 0130 00 now")
    own = guard("I invented +49 170 1234567 and DE89 3704 0044 0532 0130 00.", value)
    assert own.sentences[0].source == "model"
    assert own.sentences[0].flags == ()
    quoted = guard("It says: Call +49 170 1234567 or pay DE89 3704 0044 0532 0130 00 now", value)
    assert quoted.sentences[0].source == "untrusted"
    assert quoted.sentences[0].flags == ("untrusted_phone", "untrusted_account")


@pytest.mark.attack("A13")
def test_notices_from_filter_flags(make_value: MakeValue) -> None:
    guarded = guard(ANSWER, email_value(make_value), flags=(IGNORE, IGNORE))
    assert guarded.notices == (NOTICE,)
    other = FilterFlag(field="body", start=0, end=4, label="system_tag")
    assert len(guard(ANSWER, email_value(make_value), flags=(IGNORE, other)).notices) == 2


@pytest.mark.attack("A13")
def test_render_guarded(make_value: MakeValue) -> None:
    guarded = guard(ANSWER, email_value(make_value), flags=(IGNORE,))
    assert render_guarded(guarded) == (
        'Your bill is 120.00 EUR. [untrusted: email] "The email says: Call +49 170 1234567 to '
        'confirm." [untrusted: email] "Pay at hxxps://evil[.]example/pay"\n'
        f"notice: {NOTICE}"
    )
    assert render_guarded(guard("")) == ""
    assert (
        render_guarded(guard("", flags=(IGNORE,)))
        == f"notice: {NOTICE.replace('(email)', '(unknown)')}"
    )


@pytest.mark.invariant("I6")
def test_guard_is_pure_and_deterministic(make_value: MakeValue) -> None:
    value = email_value(make_value)
    store = {value.ref.id: value}
    before = dict(store)
    first = guard_answer(ANSWER, store, (), flags=(IGNORE,))
    second = guard_answer(ANSWER, store, (), flags=(IGNORE,))
    assert first.model_dump_json() == second.model_dump_json()
    assert store == before


@pytest.mark.attack("A13")
def test_partial_quote_by_value_sentence_matches(make_value: MakeValue) -> None:
    value = email_value(make_value, "Send the gift cards. Keep this secret.", "e1")
    guarded = guard("Someone wrote: Send the gift cards.\nUnrelated sentence here.", value)
    assert [s.source for s in guarded.sentences] == ["untrusted", "model"]
    assert guarded.sentences[0].value_ids == ("e1",)


@pytest.mark.attack("A13")
def test_whole_value_quote_still_matches(make_value: MakeValue) -> None:
    value = email_value(make_value, "Send gift cards", "e1")
    guarded = guard("The email said: send gift cards", value)
    assert guarded.sentences[0].source == "untrusted"
    assert guarded.sentences[0].value_ids == ("e1",)


@pytest.mark.attack("A13")
def test_unflagged_value_notice_without_quote(make_value: MakeValue) -> None:
    value = email_value(make_value, "Something never quoted", "c1.m9.body")
    guarded = guard("Nothing relevant here.", value, flags=(IGNORE,))
    assert guarded.notices == (NOTICE,)
    unknown = FilterFlag(field="nope", start=0, end=1, label="override")
    notice = guard("x", flags=(unknown,)).notices[0]
    assert notice.startswith("untrusted content (unknown) contained text flagged as override")


@pytest.mark.attack("A13")
def test_flag_prefers_a_quoted_value_and_reads_tool_origins(make_value: MakeValue) -> None:
    quiet = make_value("a.m1.body", "Never shown anywhere", origin="file", integrity="untrusted")
    loud = make_value(
        "b.m2.body", "Read this carefully now", origin="tool:read_file", integrity="untrusted"
    )
    guarded = guard("It said: read this carefully now", quiet, loud, flags=(IGNORE,))
    assert guarded.sentences[0].shown.startswith('[untrusted: tool:read_file] "')
    assert guarded.notices[0].startswith("untrusted content (tool:read_file) contained")


@pytest.mark.attack("A13")
def test_defang_covers_userinfo_and_port() -> None:
    assert defang("https://a.b:8080@c.d/p?q=1.2") == "hxxps://a[.]b:8080@c[.]d/p?q=1.2"
    assert defang("https://a.b/x.y#z.w") == "hxxps://a[.]b/x.y#z.w"
    assert defang("//a.b/c.d") == "//a[.]b/c.d"


@pytest.mark.attack("A13")
def test_urls_replaced_from_the_end() -> None:
    answer = "Go to https://a.example/x then maybe http://b.example/y and finish"
    sentence = guard(answer).sentences[0]
    assert sentence.defanged == ("https://a.example/x", "http://b.example/y")
    assert sentence.shown == (
        "Go to hxxps://a[.]example/x then maybe hxxp://b[.]example/y and finish"
    )
    assert sentence.flags == ("untrusted_url",)


@pytest.mark.attack("A13")
def test_link_nested_in_another_links_path_is_defanged() -> None:
    # Found by the property test: glued text puts a second link into the first one's path, which
    # `defang` keeps byte for byte, so the guard defangs the remaining copies too.
    sentence = guard("http://x.yhttp://x.y+49 170 1234567http://x.y").sentences[0]
    assert "http://x.y" not in sentence.shown
    assert sentence.flags == ("untrusted_url",)


@pytest.mark.attack("A13")
def test_url_glued_behind_another_url_is_defanged() -> None:
    glued = guard("http://x.yhttp://x.y").sentences[0]
    assert glued.shown == "hxxp://x[.]yhxxp://x[.]y"
    other = guard("http://x.yhttps://evil.example/p").sentences[0]
    assert other.shown == "hxxp://x[.]yhxxps://evil[.]example/p"
    for sentence in (glued, other):
        assert "http://" not in sentence.shown
        assert "https://" not in sentence.shown


@pytest.mark.attack("A13")
def test_untrusted_origin_label_for_tool_origin(make_value: MakeValue) -> None:
    value = make_value("f1", "Wire the funds now", origin="tool:read_file", integrity="untrusted")
    sentence = guard("The file says wire the funds now.", value).sentences[0]
    assert sentence.shown == '[untrusted: tool:read_file] "The file says wire the funds now."'


@pytest.mark.attack("A13")
def test_date_is_flagged_as_phone_in_untrusted_sentence(make_value: MakeValue) -> None:
    # Known limit of the deliberately simple phone regex: a date also looks like a phone number.
    value = email_value(make_value, "Due on 2026-12-05 sharp", "e1")
    sentence = guard("The note says: due on 2026-12-05 sharp", value).sentences[0]
    assert sentence.flags == ("untrusted_phone",)


TOKENS = (
    "http://x.y",
    "https://a.b/c",
    "evil.example/x",
    "+49 170 1234567",
    "IBAN",
    ".",
    "!",
    "\n",
    ZW,
    "hello",
    "bill",
    " ",
    "quoted words here",
)


@pytest.mark.attack("A13")
@settings(max_examples=100, deadline=None)
@example(tokens=["http://x.y", "http://x.y"])
@example(tokens=["http://x.y", "https://a.b/c"])
@example(tokens=["+49 170 1234567", ".", "http://x.y"])
@example(tokens=["https://a.b/c", "evil.example/x", "evil.example/x"])
@given(tokens=st.lists(st.sampled_from(TOKENS), max_size=14))
def test_guard_never_raises_and_defangs_everything_property(tokens: list[str]) -> None:
    store = {
        v.ref.id: v
        for v in (
            plain_value(
                "e1", "quoted words here. Visit evil.example/x today", "email", "untrusted"
            ),
            plain_value("u1", "hello bill", "user", "trusted"),
        )
    }
    guarded = guard_answer("".join(tokens), store, ())
    for sentence in guarded.sentences:
        for url in extract_urls(normalize_text(sentence.text)):
            assert url.raw not in sentence.shown
        # No token host is allowed, so no clickable scheme may survive anywhere.
        assert "http://" not in sentence.shown
        assert "https://" not in sentence.shown


@pytest.mark.invariant("I6")
def test_module_stays_out_of_models_all() -> None:
    names = {
        "GuardedSentence",
        "GuardedAnswer",
        "guard_answer",
        "split_sentences",
        "defang",
        "render_guarded",
    }
    assert names.isdisjoint(set(notary_core.models.__all__))
