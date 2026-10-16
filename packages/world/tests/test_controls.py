import pytest

from notary_core.units import canonicalize
from notary_world.attacks import (
    ALL_ATTACKS,
    ALL_CONTROLS,
    CONTROL_SCENARIOS,
    AttackNotFoundError,
    get_control,
    run_control,
)
from notary_world.cast import ACCOUNTANT_EMAIL, BILL_AMOUNT_CENTS, BILLER_IBAN
from notary_world.fakes import FakeMonitor
from notary_world.scenarios import get_scenario

CONTROL_IDS = ("B1", "B2", "B3", "B4")


@pytest.mark.attack("A14")
def test_four_controls_exist_and_are_all_allow() -> None:
    assert [c.control_id for c in ALL_CONTROLS] == list(CONTROL_IDS)
    for control in ALL_CONTROLS:
        assert all(call.expected.verdict == "ALLOW" for call in control.scripted)
        assert control.scenario_id == CONTROL_SCENARIOS[control.control_id]
        assert control.user_request == get_scenario(control.scenario_id).user_request


@pytest.mark.attack("A14")
@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_controls_are_allowed_by_the_real_monitor(control_id: str) -> None:
    run = run_control(control_id)
    assert run.ok, [c for c in run.checks if not c.matches]


@pytest.mark.attack("A14")
@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_controls_agree_with_the_fake_monitor(control_id: str) -> None:
    assert run_control(control_id, monitor=FakeMonitor((*ALL_ATTACKS, *ALL_CONTROLS))).ok


@pytest.mark.attack("A14")
def test_controls_achieve_their_user_goal_in_the_world() -> None:
    for control_id in ("B1", "B4"):
        diff = run_control(control_id).record
        (transfer,) = [
            t
            for t in diff.world_after.bank.transfers
            if t.transfer_id not in {x.transfer_id for x in diff.world_before.bank.transfers}
        ]
        assert canonicalize("iban", transfer.to_iban).value == BILLER_IBAN
        assert transfer.amount_cents == BILL_AMOUNT_CENTS
    b3 = run_control("B3").record
    assert [m.to for m in b3.world_after.sent_mails] == [ACCOUNTANT_EMAIL]
    assert run_control("B2").record.world_diff.changes == ()


@pytest.mark.attack("A14")
def test_fake_monitor_accepts_controls() -> None:
    monitor = FakeMonitor(ALL_CONTROLS)
    assert run_control("B1", monitor=monitor).ok


@pytest.mark.attack("A14")
def test_unknown_control_is_rejected() -> None:
    assert get_control("b1").control_id == "B1"
    with pytest.raises(AttackNotFoundError):
        get_control("B9")
