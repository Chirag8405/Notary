import pytest
from hypothesis import given
from hypothesis import strategies as st

from notary_core.units.iban import canonicalize_iban, iban_mod97_ok

DE = "DE89370400440532013000"
GB = "GB82WEST12345698765432"


@pytest.mark.attack("A3")
def test_canonicalize_strips_spaces_and_uppercases() -> None:
    c = canonicalize_iban("de89 3704 0044 0532 0130 00")
    assert c.unit == "iban"
    assert c.value == DE
    assert c.valid


@pytest.mark.attack("A3")
def test_known_valid_ibans() -> None:
    assert canonicalize_iban(DE).valid
    assert canonicalize_iban(GB).valid


@pytest.mark.attack("A3")
def test_mod97_failure_is_invalid() -> None:
    c = canonicalize_iban("DE89370400440532013001")
    assert c.value == "DE89370400440532013001"
    assert c.valid is False


@pytest.mark.attack("A7")
def test_zero_width_and_tag_chars_are_removed() -> None:
    sneaky = "DE89\u200b3704\U000e00410044-0532 0130\u200d00"
    assert canonicalize_iban(sneaky).value == DE
    assert canonicalize_iban(sneaky).valid


@pytest.mark.attack("A7")
def test_fullwidth_digits_normalize() -> None:
    fullwidth = "".join(chr(ord(ch) + 0xFEE0) for ch in DE)
    c = canonicalize_iban(fullwidth)
    assert c.value == DE
    assert c.valid


@pytest.mark.attack("A8")
def test_wrong_length_or_charset_is_invalid() -> None:
    assert canonicalize_iban("DE89").valid is False
    assert canonicalize_iban("DE89370400440532_13000").valid is False


@pytest.mark.attack("A3")
def test_empty_string_is_invalid_not_error() -> None:
    c = canonicalize_iban("")
    assert c.value == ""
    assert c.valid is False


@given(st.text())
@pytest.mark.attack("A3")
def test_canonicalize_is_idempotent(raw: str) -> None:
    c = canonicalize_iban(raw)
    assert canonicalize_iban(c.value) == c


@pytest.mark.attack("A7")
def test_mod97_rejects_non_ascii_digits() -> None:
    assert iban_mod97_ok("DE89370400440532013000")
    assert iban_mod97_ok("DE\uff18\uff19370400440532013000") is False
    assert iban_mod97_ok("DE89") is False
