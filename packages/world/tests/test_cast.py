import pytest

from notary_world import golden
from notary_world.cast import (
    ATTACKER_EMAIL,
    ATTACKER_HOST,
    ATTACKER_IBAN,
    ATTACKER_URL,
    BILL_AMOUNT,
    BILL_AMOUNT_CENTS,
    BILLER_IBAN,
    LOOKALIKE_BILLER_IBAN,
    SECRET_2FA_CODE,
    SECRET_API_KEY,
    USER_IBAN,
)


@pytest.mark.attack("A3")
def test_cast_matches_golden_stream_constants() -> None:
    assert ATTACKER_IBAN == golden.ATTACKER_IBAN
    assert BILLER_IBAN == golden.ACME_IBAN


@pytest.mark.attack("A8")
def test_cast_ibans_are_distinct() -> None:
    assert len({USER_IBAN, BILLER_IBAN, LOOKALIKE_BILLER_IBAN, ATTACKER_IBAN}) == 4
    assert len(LOOKALIKE_BILLER_IBAN) == len(BILLER_IBAN)
    assert LOOKALIKE_BILLER_IBAN[:-1] == BILLER_IBAN[:-1]
    assert LOOKALIKE_BILLER_IBAN[-1] != BILLER_IBAN[-1]


@pytest.mark.attack("A5")
def test_attacker_host_is_the_attacker_emails_domain() -> None:
    assert ATTACKER_EMAIL.endswith("@" + ATTACKER_HOST)
    assert ATTACKER_URL.startswith("https://" + ATTACKER_HOST + "/")


@pytest.mark.attack("A3")
def test_bill_amount_constants_agree() -> None:
    assert BILL_AMOUNT == "120.00"
    assert BILL_AMOUNT_CENTS == 12000


@pytest.mark.attack("A5")
def test_secret_constants_are_nonempty_and_distinct() -> None:
    assert SECRET_2FA_CODE
    assert SECRET_API_KEY
    assert SECRET_2FA_CODE != SECRET_API_KEY
