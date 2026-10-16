from typing import get_args

from hypothesis import given
from hypothesis import strategies as st

from notary_core.lookalike import normalize_for_match
from notary_core.models import DecisionUnit

HOST: DecisionUnit = "url_host"
IBAN = "DE89370400440532013000"


def test_case_and_invisible_chars_collapse() -> None:
    # covers: A7
    laced = "pay\u200bpal\u00ad.com\U000e0041"
    assert normalize_for_match(HOST, "PayPal.com") == normalize_for_match(HOST, laced)


def test_digit_confusables_for_domains() -> None:
    # covers: A8
    assert normalize_for_match(HOST, "paypa1.com") == normalize_for_match(HOST, "paypal.com")


def test_rn_vs_m() -> None:
    # covers: A8
    assert normalize_for_match(HOST, "rnicrosoft.com") == normalize_for_match(HOST, "microsoft.com")


def test_cyrillic_a_matches_latin_a() -> None:
    # covers: A8
    assert normalize_for_match(HOST, "p\u0430ypal.com") == normalize_for_match(HOST, "paypal.com")


def test_greek_omicron() -> None:
    # covers: A8
    assert normalize_for_match(HOST, "g\u03bfogle.com") == normalize_for_match(HOST, "google.com")


def test_cyrillic_i_matches_latin_i() -> None:
    # covers: A8
    assert normalize_for_match(HOST, "p\u0430yp\u0430\u0456.com") == normalize_for_match(
        HOST, "p\u0430yp\u0430i.com"
    )


def test_iban_digits_are_not_folded() -> None:
    # covers: A8
    swapped = IBAN[:-1] + "O"
    assert normalize_for_match("iban", IBAN) != normalize_for_match("iban", swapped)


def test_amount_digits_are_not_folded() -> None:
    # covers: A8
    assert normalize_for_match("amount", "1000") != normalize_for_match("amount", "l000")


@given(st.sampled_from(get_args(DecisionUnit)), st.text())
def test_normalize_is_idempotent(unit: DecisionUnit, s: str) -> None:
    # covers: A8
    once = normalize_for_match(unit, s)
    assert normalize_for_match(unit, once) == once
