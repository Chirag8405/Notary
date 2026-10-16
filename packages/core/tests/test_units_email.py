import pytest
from hypothesis import given
from hypothesis import strategies as st

from notary_core.units.email import canonicalize_email

_LOCAL_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.!#$%&'*+/=?^_{|}~-"
_ZW = "\u200b\u200d\u2060\ufeff"

_labels = st.from_regex(r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,10}[a-zA-Z0-9])?", fullmatch=True)
_domains = st.lists(_labels, min_size=2, max_size=4).map(".".join)
_locals = st.text(alphabet=_LOCAL_CHARS, min_size=1, max_size=20)


@st.composite
def _emails(draw: st.DrawFn) -> str:
    address = draw(_locals) + "@" + draw(_domains)
    if draw(st.booleans()):
        name = draw(st.text(alphabet="abcXYZ ", max_size=8))
        address = f"{name}<{address}>"
    if draw(st.booleans()):
        cut = draw(st.integers(min_value=0, max_value=len(address)))
        address = address[:cut] + draw(st.sampled_from(_ZW)) + address[cut:]
    return address


@pytest.mark.attack("A3")
def test_lowercases_and_strips_display_name() -> None:
    c = canonicalize_email("Alice <Alice@Example.COM>")
    assert c.unit == "email"
    assert c.value == "alice@example.com"
    assert c.valid


@pytest.mark.attack("A8")
def test_idn_domain_becomes_punycode() -> None:
    c = canonicalize_email("user@b\u00fccher.de")
    assert c.value == "user@xn--bcher-kva.de"
    assert c.valid


@pytest.mark.attack("A8")
def test_homoglyph_domain_differs_from_ascii() -> None:
    spoof = canonicalize_email("user@p\u0430ypal.com")
    plain = canonicalize_email("user@paypal.com")
    assert spoof.value != plain.value


@pytest.mark.attack("A7")
def test_zero_width_chars_removed() -> None:
    c = canonicalize_email("us\u200ber@exa\u200bmple.com")
    assert c.value == "user@example.com"
    assert c.valid


@pytest.mark.attack("A7")
def test_two_at_signs_invalid() -> None:
    assert canonicalize_email("a@b@c.com").valid is False


@pytest.mark.attack("A3")
def test_missing_domain_invalid() -> None:
    assert canonicalize_email("user@").valid is False


@pytest.mark.attack("A3")
def test_plus_tag_preserved() -> None:
    c = canonicalize_email("a+tag@x.com")
    assert c.value == "a+tag@x.com"
    assert c.valid


@pytest.mark.attack("A3")
def test_display_name_with_at_sign_uses_angle_address() -> None:
    c = canonicalize_email('"a@evil.com" <b@x.com>')
    assert c.value == "b@x.com"
    assert c.valid


@pytest.mark.attack("A3")
def test_no_dot_domain_invalid() -> None:
    assert canonicalize_email("user@localhost").valid is False


@pytest.mark.attack("A8")
def test_empty_label_invalid() -> None:
    assert canonicalize_email("user@a..com").valid is False
    assert canonicalize_email("user@x.com.").valid is False


@pytest.mark.attack("A3")
def test_local_part_over_64_invalid() -> None:
    assert canonicalize_email("a" * 65 + "@x.com").valid is False
    assert canonicalize_email("a" * 64 + "@x.com").valid is True


@pytest.mark.attack("A8")
def test_punycode_input_is_stable() -> None:
    c = canonicalize_email("user@xn--bcher-kva.de")
    assert c.value == "user@xn--bcher-kva.de"
    assert c.valid


@pytest.mark.attack("A3")
@given(_emails())
def test_idempotent(raw: str) -> None:
    c = canonicalize_email(raw)
    if c.valid:
        assert canonicalize_email(c.value) == c


@pytest.mark.attack("A3")
@given(st.text())
def test_never_raises_on_arbitrary_text(raw: str) -> None:
    assert canonicalize_email(raw).unit == "email"
