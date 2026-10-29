"""The one-time approval code: a process that reaches the control socket but cannot read the
proxy's stderr cannot approve an escalation (docs/threat-model.md, "Approvals through the MCP
proxy").

The tests drive `ControlServer.handle`, the function behind every socket line, so they need no
socket and run on any platform.
"""

import json
from pathlib import Path

import pytest

from notary_mcp_proxy.approvals import MAX_BAD_CODES, ApprovalDesk, Pending
from notary_mcp_proxy.config import ApprovalSettings
from notary_mcp_proxy.control import ERR_CODE, ControlServer
from notary_mcp_proxy.jsonrpc import JsonObject

CODE = "ABCDEFGH"


def _pending(endorsement_id: str = "e1") -> Pending:
    return Pending(
        endorsement_id=endorsement_id,
        call_id="c1",
        tool="pay_bill",
        card_text="pay 120.00",
        remaining_approvals=2,
    )


def _rig(*, require_code: bool = True) -> tuple[ApprovalDesk, ControlServer, str | None]:
    desk = ApprovalDesk(timeout_seconds=60.0, require_code=require_code, new_code=lambda: CODE)
    code = desk.open(_pending())
    return desk, ControlServer(desk, Path("unused.sock")), code


def _ask(control: ControlServer, **fields: str) -> JsonObject:
    return control.handle(json.dumps({"op": "approve", "endorsement_id": "e1", **fields}).encode())


def test_open_returns_the_code_only_when_it_is_required() -> None:
    assert _rig()[2] == CODE
    assert _rig(require_code=False)[2] is None


def test_the_code_is_in_no_card_and_no_pending_answer() -> None:
    desk, control, code = _rig()
    assert code is not None
    assert code not in json.dumps(control.handle(b'{"op": "pending"}'))
    assert [p.endorsement_id for p in desk.pending()] == ["e1"]


def test_approve_without_the_code_is_refused_and_records_nothing() -> None:
    desk, control, _ = _rig()
    assert _ask(control) == {"ok": False, "error": ERR_CODE}
    assert _ask(control, code="WRONGONE") == {"ok": False, "error": ERR_CODE}
    assert desk.pending()  # still open, nobody decided


def test_approve_with_the_code_is_recorded_once() -> None:
    desk, control, _ = _rig()
    assert _ask(control, code=CODE) == {"ok": True}
    assert desk.resolve("e1", cancelled=lambda: False).choice == "approve"


def test_the_code_ignores_case_and_surrounding_spaces() -> None:
    _, control, _ = _rig()
    assert _ask(control, code=f"  {CODE.lower()} ") == {"ok": True}


def test_a_code_that_is_not_text_is_a_bad_request() -> None:
    _, control, _ = _rig()
    reply = control.handle(b'{"op": "approve", "endorsement_id": "e1", "code": 5}')
    assert reply == {"ok": False, "error": "bad request"}


def test_guessing_ends_in_a_rejection_not_an_approval() -> None:
    desk, control, _ = _rig()
    for guess in range(MAX_BAD_CODES):
        assert _ask(control, code=f"GUESS{guess}")["ok"] is False
    assert _ask(control, code=CODE)["ok"] is False  # too late: the card is decided
    assert desk.resolve("e1", cancelled=lambda: False).choice == "reject"


def test_reject_needs_no_code() -> None:
    desk, control, _ = _rig()
    reply = control.handle(b'{"op": "reject", "endorsement_id": "e1"}')
    assert reply == {"ok": True}
    assert desk.resolve("e1", cancelled=lambda: False).choice == "reject"


def test_the_clients_own_ui_needs_no_code() -> None:
    desk, _, _ = _rig()
    assert desk.decide("e1", "approve") is True  # elicitation decides in the process


def test_without_codes_the_old_protocol_still_works() -> None:
    desk, control, _ = _rig(require_code=False)
    assert _ask(control) == {"ok": True}
    assert desk.resolve("e1", cancelled=lambda: False).choice == "approve"


def test_the_default_config_requires_a_code() -> None:
    assert ApprovalSettings().require_code is True


def test_codes_differ_per_card() -> None:
    desk = ApprovalDesk(timeout_seconds=60.0, require_code=True)
    first = desk.open(_pending("e1"))
    second = desk.open(_pending("e2"))
    assert first is not None
    assert second is not None
    assert first != second
    assert len(first) == 8


@pytest.mark.parametrize("op", ["approve", "reject"])
def test_an_unknown_card_is_unknown_before_the_code_is_looked_at(op: str) -> None:
    _, control, _ = _rig()
    reply = control.handle(json.dumps({"op": op, "endorsement_id": "e9", "code": CODE}).encode())
    assert reply["ok"] is False
    assert reply["error"] != ERR_CODE
