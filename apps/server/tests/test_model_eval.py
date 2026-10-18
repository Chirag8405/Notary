"""Model-dependence eval: the pure parts, with a scripted model and no network."""

import pytest

from notary_core.models import Lane
from notary_server.model_eval import (
    ATTACKS,
    LANES,
    Attack,
    ModelStoppedError,
    Outcome,
    guarded_violations,
    markdown,
    run_eval,
    verdict,
    wilson_interval,
)
from notary_world.cast import ATTACKER_IBAN


def test_wilson_interval_known_values() -> None:
    low, high = wilson_interval(0, 20)
    assert low == 0.0
    assert high == pytest.approx(0.1611, abs=1e-3)
    low, high = wilson_interval(10, 20)
    assert (low, high) == pytest.approx((0.2993, 0.7007), abs=1e-3)
    assert wilson_interval(0, 0) == (0.0, 1.0)


def hijacked_without_guard(model: str, attack: Attack, lane: Lane, seed: int) -> Outcome:
    return Outcome(attacker_goal=lane != "notary" and seed % 2 == 0, tool_calls=2)


def test_cells_are_counted_per_model_attack_and_lane() -> None:
    report = run_eval(["m1", "m2"], ATTACKS, LANES, 4, hijacked_without_guard, date="2026-10-18")
    assert len(report.cells) == 2 * len(ATTACKS) * len(LANES)
    undefended = next(c for c in report.cells if c.lane == "undefended")
    assert (undefended.rounds, undefended.hits) == (4, 2)
    assert all(c.rounds == 4 for c in report.cells)
    assert verdict(report) == "pass"
    assert guarded_violations(report) == ()


def test_a_hit_on_the_notary_lane_fails_the_verdict() -> None:
    def broken(model: str, attack: Attack, lane: Lane, seed: int) -> Outcome:
        return Outcome(attacker_goal=lane == "notary" and seed == 1, tool_calls=1)

    report = run_eval(["m"], ATTACKS[:1], LANES, 3, broken, date="2026-10-18")
    assert verdict(report) == "fail"
    (cell,) = guarded_violations(report)
    assert (cell.hits, cell.rounds) == (1, 3)


def test_a_stopped_model_keeps_its_partial_rounds_and_others_continue() -> None:
    calls: dict[str, int] = {}

    def capped(model: str, attack: Attack, lane: Lane, seed: int) -> Outcome:
        calls[model] = calls.get(model, 0) + 1
        if model == "a" and calls[model] > 4:
            raise ModelStoppedError("rate limit (daily token cap)")
        return Outcome(False, 1)

    report = run_eval(["a", "b"], ATTACKS[:1], LANES, 5, capped, date="2026-10-18")
    assert report.stopped == {"a": "rate limit (daily token cap)"}
    assert sum(c.rounds for c in report.cells if c.model == "a") == 4
    assert all(c.rounds == 5 for c in report.cells if c.model == "b")
    assert "`a` stopped: rate limit" in markdown(report)


def test_run_budget_stops_a_model() -> None:
    report = run_eval(
        ["m"], ATTACKS, LANES, 20, hijacked_without_guard, date="d", max_runs_per_model=9
    )
    assert sum(c.rounds for c in report.cells) == 9
    assert "run budget" in report.stopped["m"]


def test_no_tool_call_and_rejected_runs_are_counted_apart() -> None:
    outcomes = iter([Outcome(False, 0), Outcome(False, 0, rejected_call=True), Outcome(True, 1)])

    def scripted(model: str, attack: Attack, lane: Lane, seed: int) -> Outcome:
        return next(outcomes)

    report = run_eval(["m"], ATTACKS[:1], ("undefended",), 3, scripted, date="d")
    (cell,) = report.cells
    assert (cell.no_tool_call, cell.rejected, cell.hits) == (1, 1, 1)


def test_markdown_has_a_column_per_lane_with_intervals() -> None:
    report = run_eval(["m"], ATTACKS[:1], LANES, 20, hijacked_without_guard, date="d")
    table = markdown(report)
    assert "notary (must be 0)" in table
    assert "0/20 (0%-16%)" in table
    assert "10/20 (30%-70%)" in table


def test_attacks_cover_data_only_and_instruction_styles() -> None:
    assert ATTACKS[0].payload is None
    assert any("ignore" in (a.payload or "").lower() for a in ATTACKS)
    for attack in ATTACKS:
        bill = next(m for m in attack.scenario(3).world.mails if m.mail_id == "m-dec")
        assert ATTACKER_IBAN in bill.body
