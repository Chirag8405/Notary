from typing import get_args

import pytest
from hypothesis import given
from hypothesis import strategies as st

from notary_core.lookalike import normalize_for_match, osa_distance
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


def _reference_osa(a: str, b: str) -> int:
    """Independent full-matrix restricted Damerau-Levenshtein (optimal string alignment)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


@pytest.mark.attack("A8")
@given(st.text(max_size=6), st.text(max_size=6), st.integers(min_value=-2, max_value=8))
def test_osa_distance_properties(a: str, b: str, limit: int) -> None:
    capped = max(limit, 0) + 1
    d = osa_distance(a, b, limit)
    assert d == osa_distance(b, a, limit)
    assert (d == 0) == (a == b)
    assert d <= capped
    assert d >= min(abs(len(a) - len(b)), capped)


@pytest.mark.attack("A8")
@given(
    st.text(alphabet="abc", max_size=8),
    st.text(alphabet="abc", max_size=8),
    st.integers(min_value=0, max_value=8),
)
def test_osa_matches_reference_and_early_exit(a: str, b: str, limit: int) -> None:
    assert osa_distance(a, b, limit) == min(_reference_osa(a, b), limit + 1)


@pytest.mark.attack("A8")
def test_osa_is_not_a_metric_pin() -> None:
    assert osa_distance("ca", "ac", 10) == 1
    assert osa_distance("ac", "abc", 10) == 1
    assert osa_distance("ca", "abc", 10) == 3


@pytest.mark.attack("A8")
def test_osa_empty_and_negative_limit() -> None:
    assert osa_distance("", "abc", 5) == 3
    assert osa_distance("abc", "", 5) == 3
    assert osa_distance("", "abc", 2) == 3
    assert osa_distance("abc", "abd", -3) == 1
    assert osa_distance("abc", "abc", -3) == 0
