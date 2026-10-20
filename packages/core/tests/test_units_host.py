import pytest
from hypothesis import given
from hypothesis import strategies as st

from notary_core.units.host import canonicalize_host, registrable_domain

_ZW = "\u200b\u200d\u2060\ufeff"

_labels = st.from_regex(r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,10}[a-zA-Z0-9])?", fullmatch=True)
_hosts = st.lists(_labels, min_size=1, max_size=4).map(".".join)
_userinfo = st.from_regex(r"[a-z0-9.:%-]{1,8}@", fullmatch=True)
_port = st.from_regex(r":[0-9]{0,5}", fullmatch=True)
_path = st.from_regex(r"[/?#][a-z0-9/@.?=&#]{0,12}", fullmatch=True)


@st.composite
def _urls(draw: st.DrawFn) -> str:
    host = draw(_hosts)
    if draw(st.booleans()):
        cut = draw(st.integers(min_value=0, max_value=len(host)))
        host = host[:cut] + draw(st.sampled_from(_ZW)) + host[cut:]
    parts = [host]
    if draw(st.booleans()):
        parts.insert(0, draw(_userinfo))
    if draw(st.booleans()):
        parts.insert(0, draw(st.sampled_from(["http://", "https://", "//", "ftp://"])))
    if draw(st.booleans()):
        parts.append(draw(_port))
    if draw(st.booleans()):
        parts.append(draw(_path))
    return "".join(parts)


def _host(raw: str) -> str:
    return canonicalize_host(raw).value


@pytest.mark.attack("A5")
def test_userinfo_does_not_hide_the_real_host() -> None:
    c = canonicalize_host("https://trusted.com@evil.com/x")
    assert c.unit == "url_host"
    assert c.value == "evil.com"
    assert c.valid


@pytest.mark.attack("A5")
def test_backslash_trick() -> None:
    assert _host("https://evil.com\\@trusted.com") == "evil.com"


@pytest.mark.attack("A5")
def test_port_path_query_stripped() -> None:
    assert _host("https://Example.com:8443/a?b=c#d") == "example.com"


@pytest.mark.attack("A5")
def test_bare_host_accepted() -> None:
    c = canonicalize_host("Example.COM.")
    assert c.value == "example.com"
    assert c.valid


@pytest.mark.attack("A8")
def test_idn_host_punycode() -> None:
    c = canonicalize_host("b\u00fccher.de")
    assert c.value == "xn--bcher-kva.de"
    assert c.valid


@pytest.mark.attack("A7")
def test_percent_encoded_host_invalid() -> None:
    assert canonicalize_host("ex%61mple.com").valid is False


@pytest.mark.attack("A5")
def test_ipv4_and_ipv6_literals() -> None:
    v4 = canonicalize_host("http://127.0.0.1:80/")
    assert (v4.value, v4.valid) == ("127.0.0.1", True)
    v6 = canonicalize_host("http://[::1]/")
    assert (v6.value, v6.valid) == ("[::1]", True)


@pytest.mark.attack("A5")
def test_registrable_domain_simple() -> None:
    assert registrable_domain("mail.acme.example") == "acme.example"


@pytest.mark.attack("A5")
def test_registrable_domain_multipart() -> None:
    assert registrable_domain("shop.example.co.uk") == "example.co.uk"


@pytest.mark.attack("A5")
def test_registrable_domain_of_ip() -> None:
    assert registrable_domain("127.0.0.1") == "127.0.0.1"
    assert registrable_domain("[::1]") == "[::1]"


@pytest.mark.attack("A7")
@given(st.text())
def test_never_raises(raw: str) -> None:
    c = canonicalize_host(raw)
    assert c.unit == "url_host"
    assert isinstance(registrable_domain(c.value), str)


@pytest.mark.attack("A5")
def test_bare_host_with_port() -> None:
    assert _host("example.com:8443/a") == "example.com"


@pytest.mark.attack("A5")
def test_multiple_at_signs_use_last() -> None:
    assert _host("https://a@b@evil.com/") == "evil.com"


@pytest.mark.attack("A5")
def test_at_sign_in_path_is_not_userinfo() -> None:
    assert _host("https://evil.com/path@trusted.com") == "evil.com"


@pytest.mark.attack("A7")
def test_fullwidth_slash_and_tab_removed() -> None:
    assert _host("https://evil.com\uff0f@trusted.com") == "evil.com"
    assert _host("ev\til.com") == "evil.com"


@pytest.mark.attack("A7")
def test_ideographic_full_stop_trailing() -> None:
    c = canonicalize_host("example.com\u3002")
    assert c.value == "example.com"
    assert c.valid


@pytest.mark.attack("A5")
@pytest.mark.parametrize(
    "raw",
    ["http://2130706433/", "http://0x7f.1/", "http://127.0.0.01/", "http://300.1.1.1/"],
)
def test_numeric_hosts_are_invalid(raw: str) -> None:
    assert canonicalize_host(raw).valid is False


@pytest.mark.attack("A7")
def test_label_and_total_length_limits() -> None:
    assert canonicalize_host("a" * 63 + ".com").valid is True
    assert canonicalize_host("a" * 64 + ".com").valid is False
    long_host = ".".join(["a" * 50] * 6)
    assert len(long_host) > 253
    assert canonicalize_host(long_host).valid is False


@pytest.mark.attack("A7")
@pytest.mark.parametrize("raw", ["", "https:///x", "https:evil.com"])
def test_empty_and_no_match_invalid(raw: str) -> None:
    assert canonicalize_host(raw).valid is False


@pytest.mark.attack("A5")
def test_registrable_domain_edges() -> None:
    assert registrable_domain("co.uk") == "co.uk"
    assert registrable_domain("example.co.uk") == "example.co.uk"
    assert registrable_domain("shop.example.com.sg") == "example.com.sg"


@pytest.mark.attack("A8")
@given(_urls())
def test_valid_results_are_idempotent(raw: str) -> None:
    c = canonicalize_host(raw)
    if c.valid:
        assert canonicalize_host(c.value) == c
