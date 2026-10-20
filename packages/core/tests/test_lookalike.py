from typing import get_args

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from notary_core._confusables_data import SKELETON
from notary_core.lookalike import (
    CONFUSABLES,
    LOOKALIKE_CONFIG,
    MULTI_CONFUSABLES,
    is_lookalike,
    nearest_known,
    normalize_for_match,
    osa_distance,
)
from notary_core.models import DecisionUnit

HOST: DecisionUnit = "url_host"
IBAN = "DE89370400440532013000"


@pytest.mark.attack("A7")
def test_case_and_invisible_chars_collapse() -> None:
    laced = "pay\u200bpal\u00ad.com\U000e0041"
    assert normalize_for_match(HOST, "PayPal.com") == normalize_for_match(HOST, laced)


@pytest.mark.attack("A8")
def test_digit_confusables_for_domains() -> None:
    assert normalize_for_match(HOST, "paypa1.com") == normalize_for_match(HOST, "paypal.com")


@pytest.mark.attack("A8")
def test_rn_vs_m() -> None:
    assert normalize_for_match(HOST, "rnicrosoft.com") == normalize_for_match(HOST, "microsoft.com")


@pytest.mark.attack("A8")
def test_cyrillic_a_matches_latin_a() -> None:
    assert normalize_for_match(HOST, "p\u0430ypal.com") == normalize_for_match(HOST, "paypal.com")


@pytest.mark.attack("A8")
def test_greek_omicron() -> None:
    assert normalize_for_match(HOST, "g\u03bfogle.com") == normalize_for_match(HOST, "google.com")


@pytest.mark.attack("A8")
def test_cyrillic_i_matches_latin_i() -> None:
    assert normalize_for_match(HOST, "p\u0430yp\u0430\u0456.com") == normalize_for_match(
        HOST, "p\u0430yp\u0430i.com"
    )


@pytest.mark.attack("A8")
def test_iban_digits_are_not_folded() -> None:
    swapped = IBAN[:-1] + "O"
    assert normalize_for_match("iban", IBAN) != normalize_for_match("iban", swapped)


@pytest.mark.attack("A8")
def test_amount_digits_are_not_folded() -> None:
    assert normalize_for_match("amount", "1000") != normalize_for_match("amount", "l000")


@given(st.sampled_from(get_args(DecisionUnit)), st.text())
@pytest.mark.attack("A8")
def test_normalize_is_idempotent(unit: DecisionUnit, s: str) -> None:
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


def _swap_last_chars(iban: str, tail: str) -> str:
    return iban[: -len(tail)] + tail


@pytest.mark.attack("A8")
def test_iban_one_digit_off_is_lookalike() -> None:
    m = is_lookalike("iban", "DE89370400440532013001", [IBAN])
    assert m is not None
    assert m.known == IBAN
    assert m.distance == 1
    assert m.confusable_equal is False


@pytest.mark.attack("A8")
def test_iban_two_edits_still_lookalike_but_three_not() -> None:
    two = is_lookalike("iban", _swap_last_chars(IBAN, "11"), [IBAN])
    assert two is not None
    assert two.distance == 2
    assert is_lookalike("iban", _swap_last_chars(IBAN, "111"), [IBAN]) is None


@pytest.mark.attack("A8")
def test_iban_different_length_not_lookalike() -> None:
    assert is_lookalike("iban", IBAN[:-1], [IBAN]) is None


@pytest.mark.attack("A8")
def test_paypa1_domain_is_lookalike() -> None:
    m = is_lookalike(HOST, "paypa1.com", ["paypal.com"])
    assert m is not None
    assert m.confusable_equal is True
    assert m.distance == 0


@pytest.mark.attack("A8")
def test_one_edit_domain_is_lookalike() -> None:
    m = is_lookalike(HOST, "paypall.com", ["paypal.com"])
    assert m is not None
    assert m.distance == 1
    assert m.confusable_equal is False


@pytest.mark.attack("A8")
def test_genuinely_different_value_is_not_lookalike() -> None:
    assert is_lookalike(HOST, "acme.example", ["paypal.com"]) is None
    assert is_lookalike("iban", "GB82WEST12345698765432", [IBAN]) is None


@pytest.mark.attack("A8")
def test_short_values_need_confusable_equality() -> None:
    assert is_lookalike(HOST, "a.com", ["b.com"]) is None


@pytest.mark.attack("A8")
def test_exact_match_is_not_a_lookalike() -> None:
    assert is_lookalike(HOST, "paypal.com", ["paypal.com"]) is None


@pytest.mark.attack("A8")
def test_transposition_counts_as_one_edit() -> None:
    m = is_lookalike(HOST, "paypla.com", ["paypal.com"])
    assert m is not None
    assert m.distance == 1


@pytest.mark.attack("A8")
def test_differing_positions_reported() -> None:
    m = is_lookalike(HOST, "paypa1.com", ["paypal.com"])
    assert m is not None
    assert m.differing_positions == (5,)
    iban = is_lookalike("iban", "DE89370400440532013001", [IBAN])
    assert iban is not None
    assert iban.differing_positions == (21,)


@pytest.mark.invariant("I6")
def test_is_lookalike_is_deterministic() -> None:
    known = ["paypal.com", "paypa1.net"]
    assert is_lookalike(HOST, "paypall.com", known) == is_lookalike(HOST, "paypall.com", known)
    assert nearest_known(HOST, "paypall.com", known) == nearest_known(HOST, "paypall.com", known)


@pytest.mark.attack("A8")
def test_nearest_known_returns_closest_even_when_far() -> None:
    result = nearest_known(HOST, "completely-different.org", ["paypal.com", "completely.org"])
    assert result is not None
    assert result[0] == "completely.org"
    assert result[1]
    assert all(0 <= i < len("completely-different.org") for i in result[1])


@pytest.mark.attack("A8")
def test_nearest_known_empty_known_is_none() -> None:
    assert nearest_known(HOST, "paypal.com", []) is None


@pytest.mark.attack("A8")
def test_nearest_known_returns_exact_match_at_distance_zero() -> None:
    assert nearest_known(HOST, "paypal.com", ["paypa1.net", "paypal.com"]) == ("paypal.com", ())


@pytest.mark.attack("A8")
def test_config_covers_every_decision_unit() -> None:
    assert set(LOOKALIKE_CONFIG) == set(get_args(DecisionUnit))


@pytest.mark.attack("A8")
@pytest.mark.parametrize("unit", get_args(DecisionUnit))
def test_config_fold_flag_matches_normalizer(unit: DecisionUnit) -> None:
    folds = normalize_for_match(unit, "1") == normalize_for_match(unit, "l")
    assert LOOKALIKE_CONFIG[unit].fold_confusables is folds


@pytest.mark.attack("A8")
def test_iban_zero_vs_letter_o_is_edit_not_confusable() -> None:
    m = is_lookalike("iban", IBAN[:-1] + "O", [IBAN])
    assert m is not None
    assert m.distance == 1
    assert m.confusable_equal is False


@pytest.mark.attack("A8")
def test_amount_is_never_a_lookalike() -> None:
    assert is_lookalike("amount", "120.00", ["120.01", "120.00", "1200.00"]) is None


@pytest.mark.attack("A8")
def test_smallest_distance_wins_and_ties_go_first() -> None:
    best = is_lookalike(HOST, "paypa1.com", ["paypall.com", "paypal.com"])
    assert best is not None
    assert best.known == "paypal.com"
    assert best.distance == 0
    tie = is_lookalike(HOST, "paypal.com", ["paypall.com", "paypaal.com"])
    assert tie is not None
    assert tie.known == "paypall.com"


@pytest.mark.attack("A8")
def test_differing_positions_for_missing_character() -> None:
    m = is_lookalike(HOST, "paypal.com", ["paypall.com"])
    assert m is not None
    assert m.differing_positions
    assert all(0 <= i < len("paypal.com") for i in m.differing_positions)
    assert nearest_known(HOST, "", ["paypal.com"]) == ("paypal.com", ())


@pytest.mark.attack("A8")
def test_differing_positions_long_strings_not_junked() -> None:
    known = "ab" * 150
    candidate = known[:150] + "z" + known[150:]
    first = nearest_known("identifier", candidate, [known])
    assert first == (known, (150,))
    assert nearest_known("identifier", candidate, [known]) == first


@pytest.mark.attack("A8")
def test_idn_homoglyph_host_is_lookalike() -> None:
    candidate = "p\u0430ypal.com".encode("idna").decode("ascii")
    assert candidate.startswith("xn--")
    m = is_lookalike(HOST, candidate, ["paypal.com"])
    assert m is not None
    assert m.confusable_equal is True
    assert m.known == "paypal.com"


@pytest.mark.attack("A8")
def test_idn_homoglyph_email_is_lookalike() -> None:
    domain = "p\u0430ypal.com".encode("idna").decode("ascii")
    m = is_lookalike("email", "user@" + domain, ["user@paypal.com"])
    assert m is not None
    assert m.confusable_equal is True


@pytest.mark.attack("A8")
def test_plain_ascii_idn_unaffected() -> None:
    assert is_lookalike(HOST, "xn--bcher-kva.de", ["xn--bcher-kva.de"]) is None
    # Decoded, "b\u00fccher.de" is one edit from "bucher.de", so it is flagged.
    m = is_lookalike(HOST, "xn--bcher-kva.de", ["bucher.de"])
    assert m is not None
    assert (m.distance, m.confusable_equal) == (1, False)


@pytest.mark.attack("A8")
@given(
    st.sampled_from(get_args(DecisionUnit)),
    st.text(),
    st.lists(st.text(), max_size=4),
)
def test_is_lookalike_and_nearest_known_never_raise(
    unit: DecisionUnit, candidate: str, known: list[str]
) -> None:
    match = is_lookalike(unit, candidate, known)
    if match is not None:
        assert match.distance >= 0
        assert all(0 <= i < len(candidate) for i in match.differing_positions)
    nearest = nearest_known(unit, candidate, known)
    if nearest is None:
        assert not known
    else:
        assert nearest[0] in known
        assert all(0 <= i < len(candidate) for i in nearest[1])


# --- Unicode confusables data (issue #299) -----------------------------------------------


def _norm(s: str) -> str:
    return normalize_for_match(HOST, s)


_REVERSE: dict[str, list[str]] = {}
for _key, _value in sorted(SKELETON.items()):
    if len(_value) == 1:
        _REVERSE.setdefault(_value, []).append(_key)
# Letters the table never rewrites and that no sequence rule touches (not r, n, v, c, l, i).
_STABLE_LETTERS = "abdefghjkmopqstuwxyz"


@pytest.mark.attack("A8")
@pytest.mark.parametrize(
    ("lookalike", "genuine"),
    [
        ("\u0440\u0430\u0443\u0440\u0430\u04cf.com", "paypal.com"),  # Cyrillic, palochka as l
        ("\u0440\u0430ypa\u04cf.com", "paypal.com"),
        ("\u03c1ay\u03c1al.com", "paypal.com"),  # Greek rho
        ("g\u03bf\u03bfgle.com", "google.com"),  # Greek omicron twice
        ("\u0261oogle.com", "google.com"),  # Latin script g, listed by Unicode only
        ("g\u0585\u0585gle.com", "google.com"),  # Armenian oh
        ("\uff50\uff41\uff59\uff50\uff41\uff4c.\uff43\uff4f\uff4d", "paypal.com"),  # fullwidth
        ("\U0001d429\U0001d41a\U0001d432\U0001d429\U0001d41a\U0001d425.com", "paypal.com"),  # bold
        ("my\u2010bank.com", "my-bank.com"),  # hyphen lookalike
        ("exampl\u0435.com", "example.com"),  # Cyrillic e
    ],
)
def test_script_and_width_lookalikes_of_a_domain(lookalike: str, genuine: str) -> None:
    assert _norm(lookalike) == _norm(genuine)


@pytest.mark.attack("A8")
def test_name_lookalikes_share_a_skeleton() -> None:
    genuine = normalize_for_match("identifier", "Alice Smith")
    for variant in (
        "A\u04cfice Smith",  # palochka for l
        "\u0410lice Smith",  # Cyrillic capital A
        "Al\u0456ce Smith",  # Cyrillic i
        "Alice Sm\u0456th",
        "\uff21lice Smith",  # fullwidth A
        "Alic\u0435 \u0455mith",  # Cyrillic e and dze
    ):
        assert normalize_for_match("identifier", variant) == genuine, variant


@pytest.mark.attack("A8")
def test_homoglyph_domain_name_and_email_are_flagged() -> None:
    domain = is_lookalike(HOST, "p\u0430yp\u0430\u04cf.com", ["paypal.com"])
    assert domain is not None
    assert (domain.distance, domain.confusable_equal) == (0, True)
    name = is_lookalike("identifier", "\u0410lic\u0435 Smith", ["Alice Smith"])
    assert name is not None
    assert name.confusable_equal is True
    email = is_lookalike("email", "al\u0456ce@example.com", ["alice@example.com"])
    assert email is not None
    assert email.confusable_equal is True


@pytest.mark.attack("A8")
def test_distinct_names_and_domains_stay_distinct() -> None:
    assert _norm("paypal.com") != _norm("paypa.com")
    assert _norm("example.com") != _norm("example.org")
    assert is_lookalike("identifier", "Bob Jones", ["Alice Smith"]) is None


@pytest.mark.attack("A8")
def test_exact_units_still_ignore_the_confusables_table() -> None:
    for unit in ("iban", "amount"):
        assert normalize_for_match(unit, "\u043e") != normalize_for_match(unit, "o")
        assert normalize_for_match(unit, "1") != normalize_for_match(unit, "l")
        assert normalize_for_match(unit, "0") != normalize_for_match(unit, "o")
    cyrillic_e = is_lookalike("iban", IBAN.replace("DE", "D\u0415"), [IBAN])
    assert cyrillic_e is not None  # one edit, not a fold
    assert cyrillic_e.confusable_equal is False


@pytest.mark.attack("A8")
@given(
    st.text(alphabet=st.sampled_from(sorted(SKELETON)) | st.sampled_from("abc01 .-"), max_size=24)
)
def test_normalize_is_idempotent_over_table_characters(s: str) -> None:
    for unit in get_args(DecisionUnit):
        once = normalize_for_match(unit, s)
        assert normalize_for_match(unit, once) == once


@pytest.mark.attack("A8")
@given(st.data())
def test_identical_skeletons_compare_equal(data: st.DataObject) -> None:
    base = data.draw(st.text(alphabet=_STABLE_LETTERS, min_size=8, max_size=16))
    variant = "".join(data.draw(st.sampled_from([ch, *_REVERSE.get(ch, [])])) for ch in base)
    assert _norm(variant) == _norm(base) == base
    if variant != base:
        match = is_lookalike(HOST, variant, [base])
        assert match is not None
        assert (match.distance, match.confusable_equal) == (0, True)


@pytest.mark.attack("A8")
@given(st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126)))
def test_ascii_input_unchanged_apart_from_case_and_documented_rules(s: str) -> None:
    folded = s.casefold()
    assume(not any(ch in CONFUSABLES for ch in folded))
    assume(not any(old in folded for old, _new in MULTI_CONFUSABLES))
    assert _norm(s) == folded


@pytest.mark.attack("A8")
def test_ascii_confusable_characters_are_exactly_the_documented_set() -> None:
    assert {ch for ch in CONFUSABLES if ch.isascii()} == {"0", "1", "5", "i", "|"}
    assert [_norm(ch) for ch in "015i|"] == ["o", "l", "s", "l", "l"]
    # The sequence rules run in their own direction: upstream's m -> rn is not applied.
    assert "m" not in CONFUSABLES
    assert _norm("rn") == _norm("m") == "m"
