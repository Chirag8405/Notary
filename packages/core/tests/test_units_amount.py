from decimal import Decimal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from notary_core.units.amount import CanonicalAmount, canonicalize_amount, to_cents


def _value(raw: str) -> Decimal | None:
    return canonicalize_amount(raw).value


@pytest.mark.attack("A3")
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("120.00", Decimal("120.00")),
        ("1,200.50", Decimal("1200.50")),
        ("1.200,50", Decimal("1200.50")),
        ("1 200,50", Decimal("1200.50")),
    ],
)
def test_plain_and_thousands_formats(raw: str, expected: Decimal) -> None:
    c = canonicalize_amount(raw)
    assert c.value == expected
    assert c.valid


@pytest.mark.attack("A3")
@pytest.mark.parametrize(
    ("raw", "value", "currency"),
    [
        ("\u20ac120", Decimal("120"), "EUR"),
        ("120 EUR", Decimal("120"), "EUR"),
        ("EUR 120.00", Decimal("120.00"), "EUR"),
        ("$5", Decimal("5"), "USD"),
        ("\u00a35", Decimal("5"), "GBP"),
        ("\u00a5500", Decimal("500"), "JPY"),
        ("5", Decimal("5"), None),
    ],
)
def test_currency_symbol_and_code(raw: str, value: Decimal, currency: str | None) -> None:
    c = canonicalize_amount(raw)
    assert c.value == value
    assert c.currency == currency
    assert c.valid


@pytest.mark.attack("A3")
def test_ambiguous_comma_rules() -> None:
    assert _value("1,234") == Decimal("1234")
    assert _value("12,5") == Decimal("12.5")


@pytest.mark.attack("A9")
@pytest.mark.parametrize("raw", ["-5", "12abc", "+5", "1e5", "5-", "(5)", "", "EUR", "$", "."])
def test_negative_and_garbage_invalid(raw: str) -> None:
    c = canonicalize_amount(raw)
    assert c.valid is False
    assert c.value is None


@pytest.mark.attack("A9")
def test_to_cents_exact() -> None:
    assert to_cents(canonicalize_amount("120.00")) == 12000
    assert to_cents(canonicalize_amount("0.005")) is None
    assert to_cents(canonicalize_amount("1200.500")) == 120050
    assert to_cents(canonicalize_amount("-5")) is None


@pytest.mark.attack("A9")
def test_huge_amount_parses() -> None:
    c = canonicalize_amount("99999999999.99")
    assert c.value == Decimal("99999999999.99")
    assert to_cents(c) == 9999999999999


@pytest.mark.attack("A9")
def test_to_cents_is_exact_beyond_28_digits() -> None:
    assert to_cents(canonicalize_amount("12345678901234567890123456789012.005")) is None
    assert to_cents(canonicalize_amount("12345678901234567890123456789012.50")) == (
        1234567890123456789012345678901250
    )


@pytest.mark.attack("A3")
@pytest.mark.parametrize(
    "raw", ["1,2,3", "1.200.50", "1.200,50,3", "0,005", "1,2345", "12,", ".", ",", "1..2", ""]
)
def test_separator_invalid_cases(raw: str) -> None:
    assert canonicalize_amount(raw).valid is False


@pytest.mark.attack("A3")
def test_separator_edge_cases() -> None:
    assert _value("1.200.500") == Decimal("1200500")
    assert _value("0,50") == Decimal("0.50")
    assert _value("100,000") == Decimal("100000")
    assert _value("007") == Decimal("7")


@pytest.mark.attack("A7")
@pytest.mark.parametrize("raw", ["\u0663", "\u0661\u0662\u0663"])
def test_non_ascii_digits_invalid(raw: str) -> None:
    assert canonicalize_amount(raw).valid is False


@pytest.mark.attack("A7")
def test_invisible_chars_do_not_change_result() -> None:
    c = canonicalize_amount("E\u200bUR 1\u200b200.50")
    assert c.value == Decimal("1200.50")
    assert c.currency == "EUR"
    for code in (0x2009, 0x00A0, 0x202F):
        assert _value(f"1{chr(code)}200,50") == Decimal("1200.50")


@pytest.mark.attack("A3")
@pytest.mark.parametrize("raw", ["EUR 5 EUR", "\u20ac5 USD", "$$5"])
def test_two_currency_markers_invalid(raw: str) -> None:
    assert canonicalize_amount(raw).valid is False


@pytest.mark.attack("A3")
def test_length_cap() -> None:
    assert canonicalize_amount("1" * 64).valid is True
    assert canonicalize_amount("1" * 65).valid is False


@pytest.mark.attack("A7")
@given(st.text())
def test_never_raises(raw: str) -> None:
    c = canonicalize_amount(raw)
    assert isinstance(c, CanonicalAmount)
    cents = to_cents(c)
    assert cents is None or isinstance(cents, int)


@pytest.mark.attack("A7")
@given(st.text())
def test_amount_text_is_ascii_only_property(raw: str) -> None:
    c = canonicalize_amount(raw)
    if c.valid:
        assert isinstance(c.value, Decimal)
