import hashlib

import pytest

from notary_core.ledger import entries_for, find_exact
from notary_core.models import (
    DecisionUnit,
    Label,
    LedgerEntry,
    LedgerSource,
    UserAuthoredSource,
    UserOrigin,
    ValueRef,
)

IBAN = "DE89370400440532013000"
EMAIL = "alice@example.com"
HOST = "example.com"
IDENT = "acme utilities"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _entry(
    unit: DecisionUnit,
    canonical: str,
    *,
    entry_id: str = "e1",
    ledger: str = "payees",
    source: LedgerSource | None = None,
) -> LedgerEntry:
    label = Label(
        origin=UserOrigin(kind="user"), integrity="trusted", readers=("*",), span_pointer=None
    )
    return LedgerEntry(
        entry_id=entry_id,
        ledger=ledger,
        key="Acme",
        value=ValueRef(id=f"v-{entry_id}", label=label, content_hash=_sha(canonical)),
        unit=unit,
        canonical=canonical,
        source=source or UserAuthoredSource(kind="user_authored"),
    )


@pytest.mark.attack("A3")
def test_find_exact_matches_canonical_only() -> None:
    entry = _entry("iban", IBAN)
    ledger = (entry,)
    assert find_exact(ledger, "iban", IBAN) == entry
    assert find_exact(ledger, "iban", "DE89 3704 0044 0532 0130 00") is None
    assert find_exact(ledger, "iban", "DE89370400440532013001") is None


@pytest.mark.attack("A3")
def test_entries_for_filters_by_unit_and_name() -> None:
    a = _entry("iban", IBAN, entry_id="e1", ledger="payees")
    b = _entry("email", EMAIL, entry_id="e2", ledger="payees")
    c = _entry("iban", "GB82WEST12345698765432", entry_id="e3", ledger="contacts")
    d = _entry("iban", "DE00ACME00000000000001", entry_id="e4", ledger="payees")
    ledger = [a, b, c, d]
    assert entries_for(ledger, "iban") == (a, c, d)
    assert entries_for(ledger, "iban", "payees") == (a, d)
    assert entries_for(ledger, "email", "contacts") == ()
    assert entries_for(ledger, "email") == (b,)


@pytest.mark.attack("A8")
def test_find_exact_does_not_fold_lookalikes() -> None:
    ledger = (_entry("url_host", "paypal.com"),)
    assert find_exact(ledger, "url_host", "paypal.com") is not None
    assert find_exact(ledger, "url_host", "paypa1.com") is None
