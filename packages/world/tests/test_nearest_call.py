"""`_nearest_call`: the call proposed again when the user asks for the nearest known value."""

from notary_core.models import DiffCard, DiffRow, EmailOrigin
from notary_world.executor import _nearest_call  # pyright: ignore[reportPrivateUsage]
from notary_world.tools import RawToolCall

CALL = RawToolCall(
    call_id="c2",
    tool="pay_bill",
    args={"payee": "DE00ATTACKER0000000001", "amount": "120.00"},
)


def row(param: str, nearest: str | None) -> DiffRow:
    return DiffRow(
        param=param,
        value_id=f"c2.arg.{param}",
        origin=EmailOrigin(kind="email"),
        integrity="untrusted",
        preview="x",
        nearest_ledger_value=nearest,
        differing_positions=(),
    )


def test_every_card_row_takes_the_nearest_known_value() -> None:
    replacement = _nearest_call(CALL, DiffCard(rows=(row("payee", "DE00ACME00000000000001"),)))
    assert replacement == RawToolCall(
        call_id="c2.nearest",
        tool="pay_bill",
        args={"payee": "DE00ACME00000000000001", "amount": "120.00"},
    )


def test_there_is_no_replacement_without_a_known_value_for_every_row() -> None:
    assert _nearest_call(CALL, None) is None
    assert _nearest_call(CALL, DiffCard(rows=())) is None
    assert _nearest_call(CALL, DiffCard(rows=(row("payee", None),))) is None
    assert _nearest_call(CALL, DiffCard(rows=(row("memo", "x"),))) is None
    two = DiffCard(rows=(row("payee", "DE00ACME00000000000001"), row("amount", None)))
    assert _nearest_call(CALL, two) is None
