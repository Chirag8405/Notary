"""Unit normalizers: canonical forms and validity checks for decision units."""

from typing import assert_never

from notary_core.models import DecisionUnit
from notary_core.units.amount import CanonicalAmount, canonicalize_amount, to_cents
from notary_core.units.email import canonicalize_email
from notary_core.units.host import canonicalize_host, registrable_domain
from notary_core.units.iban import canonicalize_iban, iban_mod97_ok
from notary_core.units.identifier import canonicalize_identifier
from notary_core.units.types import Canonical

__all__ = [
    "Canonical",
    "CanonicalAmount",
    "canonicalize",
    "canonicalize_amount",
    "canonicalize_email",
    "canonicalize_host",
    "canonicalize_iban",
    "canonicalize_identifier",
    "iban_mod97_ok",
    "registrable_domain",
    "to_cents",
]


def _amount_text(amount: CanonicalAmount) -> str:
    cents = to_cents(amount)
    if cents is not None:
        return f"{cents // 100}.{cents % 100:02d}"
    if amount.value is None:
        return ""
    plain = format(amount.value, "f")
    return plain.rstrip("0") if "." in plain else plain


def _canonicalize_amount_unit(raw: str) -> Canonical:
    # Single-currency assumption: the currency is parsed but dropped here.
    amount = canonicalize_amount(raw)
    if not amount.valid:
        return Canonical("amount", raw.strip(), False)
    return Canonical("amount", _amount_text(amount), True)


def canonicalize(unit: DecisionUnit, raw: str) -> Canonical:
    match unit:
        case "iban":
            return canonicalize_iban(raw)
        case "email":
            return canonicalize_email(raw)
        case "url_host":
            return canonicalize_host(raw)
        case "amount":
            return _canonicalize_amount_unit(raw)
        case "identifier":
            return canonicalize_identifier(raw)
        case _:
            assert_never(unit)
