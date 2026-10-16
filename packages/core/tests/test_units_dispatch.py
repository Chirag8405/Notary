from typing import get_args

import pytest
from hypothesis import given
from hypothesis import strategies as st

from notary_core.models import DecisionUnit
from notary_core.units import canonicalize, canonicalize_identifier

_UNITS: tuple[DecisionUnit, ...] = get_args(DecisionUnit)
_OWNED_UNITS: tuple[DecisionUnit, ...] = ("amount", "identifier")


@pytest.mark.attack("A3")
@pytest.mark.invariant("I2")
@pytest.mark.parametrize("unit", _UNITS)
def test_dispatch_covers_every_decision_unit(unit: DecisionUnit) -> None:
    assert canonicalize(unit, "x").unit == unit


@pytest.mark.attack("A7")
def test_identifier_casefold_and_collapse() -> None:
    c = canonicalize_identifier("  ACME   Utilities ")
    assert c.value == "acme utilities"
    assert c.valid
    for empty in ("", "   ", "\u200b"):
        e = canonicalize_identifier(empty)
        assert e.value == ""
        assert e.valid is False


@pytest.mark.attack("A7")
@pytest.mark.invariant("I2")
@pytest.mark.parametrize(
    ("unit", "plain", "laced"),
    [
        ("iban", "DE89370400440532013000", "DE89\u200b3704\u200b0044 0532 0130\u200d00"),
        ("email", "alice@example.com", "al\u200bice@exa\u200bmple.com"),
        ("url_host", "https://example.com/x", "https://exa\u200bmple.com/x"),
        ("amount", "1,200.50", "1\u200b,200.\u200b50"),
        ("identifier", "acme utilities", "ac\u200bme  Utilities"),
    ],
)
def test_obfuscated_and_plain_inputs_canonicalize_equal(
    unit: DecisionUnit, plain: str, laced: str
) -> None:
    a, b = canonicalize(unit, plain), canonicalize(unit, laced)
    assert (a.value, a.valid) == (b.value, b.valid)


@pytest.mark.attack("A7")
@given(st.sampled_from(_UNITS), st.text())
def test_canonicalize_is_total(unit: DecisionUnit, raw: str) -> None:
    assert canonicalize(unit, raw).unit == unit


@pytest.mark.attack("A7")
@given(st.text())
def test_identifier_is_idempotent(raw: str) -> None:
    c = canonicalize_identifier(raw)
    assert canonicalize_identifier(c.value) == c


@pytest.mark.attack("A3")
@pytest.mark.parametrize(
    ("raw", "value", "valid"),
    [
        ("\u20ac1,200.5", "1200.50", True),
        ("0.005", "0.005", True),
        ("0.0000001", "0.0000001", True),
        ("abc", "abc", False),
    ],
)
def test_amount_dispatch_strings(raw: str, value: str, valid: bool) -> None:
    c = canonicalize("amount", raw)
    assert (c.value, c.valid) == (value, valid)


@pytest.mark.attack("A7")
@given(st.sampled_from(_OWNED_UNITS), st.text())
def test_valid_dispatch_results_are_stable(unit: DecisionUnit, raw: str) -> None:
    c = canonicalize(unit, raw)
    if c.valid:
        assert canonicalize(unit, c.value) == c


@pytest.mark.attack("A7")
@given(st.sampled_from(_UNITS), st.text())
def test_valid_dispatch_results_are_stable_all_units(unit: DecisionUnit, raw: str) -> None:
    c = canonicalize(unit, raw)
    if c.valid:
        assert canonicalize(unit, c.value) == c
