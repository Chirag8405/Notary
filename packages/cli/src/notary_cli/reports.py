"""Attack reports: run one attack or control and condense the outcome into a plain model.

All computation lives in `notary_world`; this module only wires the oracle to the run and maps
the result to an `AttackReport` that the renderers and `--json` print.
"""

from typing import Literal

from notary_core.models import ExpectedOutcome, NotaryModel, OracleResult, OracleUpdated
from notary_core.monitor import Monitor
from notary_world.attacks import (
    ALL_ATTACKS,
    ALL_CONTROLS,
    ATTACK_NAMES,
    KNOWN_REAL_MONITOR_DEVIATIONS,
    AttackRun,
    deciding_step,
    get_attack,
    get_control,
    run_attack,
    run_control,
)
from notary_world.executor import OracleFn, RunRecord, default_monitor
from notary_world.fakes import FakeMonitor
from notary_world.invariants import check_invariants
from notary_world.models import ScriptedCall
from notary_world.oracle import GoalPair, evaluate, goal_status

MonitorChoice = Literal["real", "fake"]
GoalState = Literal["reached", "not_reached", "deferred"]

CONTROL_ATTACKER_GOAL = "attacker:pay_attacker_iban"
"""The attacker goal a benign control is judged against (it must stay not reached)."""


class ReportCheck(NotaryModel):
    call_id: str
    tool: str
    expected: ExpectedOutcome
    actual: ExpectedOutcome | None
    matches: bool
    known_deviation: str | None
    """Reason from `KNOWN_REAL_MONITOR_DEVIATIONS` when this call mismatches, else None."""


class AttackReport(NotaryModel):
    attack_id: str
    """"A1".."A14" or "B1".."B4"."""
    name: str
    monitor: MonitorChoice
    ok: bool
    deferred: bool
    deciding_step: str
    """A `CHECK_ORDER` name, `"none"` (ALLOW) or `"output_guard"` (deferred A13)."""
    expected_verdict: str
    checks: tuple[ReportCheck, ...]
    oracle: OracleResult
    attacker_goal: GoalState
    user_goal: GoalState


def monitor_for(choice: MonitorChoice) -> Monitor:
    """The real `decide` by default; the fixture-driven fake only when asked for."""
    if choice == "fake":
        return FakeMonitor((*ALL_ATTACKS, *ALL_CONTROLS))
    return default_monitor()


def _oracle_for(goals: GoalPair, monitor: Monitor) -> OracleFn:
    def oracle(run: RunRecord) -> OracleResult:
        return evaluate(run, goals, check_invariants(run, monitor))

    return oracle


def _recorded_oracle(record: RunRecord, goals: GoalPair, monitor: Monitor) -> OracleResult:
    """The result the run itself logged; recomputed only if the run halted before logging it."""
    logged = next((e.result for e in reversed(record.events) if isinstance(e, OracleUpdated)), None)
    if logged is not None:
        return logged
    return evaluate(record, goals, check_invariants(record, monitor))


def _checks(run: AttackRun, scripted: tuple[ScriptedCall, ...]) -> tuple[ReportCheck, ...]:
    tools = {call.call_id: call.tool for call in scripted}
    return tuple(
        ReportCheck(
            call_id=check.call_id,
            tool=tools[check.call_id],
            expected=check.expected,
            actual=check.actual,
            matches=check.matches,
            known_deviation=(
                None if check.matches else KNOWN_REAL_MONITOR_DEVIATIONS.get(check.call_id)
            ),
        )
        for check in run.checks
    )


def build_report(attack_id: str, choice: MonitorChoice) -> tuple[AttackReport, RunRecord]:
    """Run an attack (`A1`..`A14`) or a control (`B1`..`B4`); raises `AttackNotFoundError`."""
    wanted = attack_id.upper()
    monitor = monitor_for(choice)
    if wanted.startswith("B"):
        control = get_control(wanted)
        goals = GoalPair(attacker_goal_id=CONTROL_ATTACKER_GOAL, user_goal_id=control.user_goal_id)
        run = run_control(wanted, monitor=monitor, oracle=_oracle_for(goals, monitor))
        last = control.scripted[-1].expected
        name, scripted = control.title, control.scripted
        verdict, step = last.verdict, last.deciding_check or "none"
    else:
        fixture = get_attack(wanted)
        goals = GoalPair(
            attacker_goal_id=fixture.attacker_goal_id, user_goal_id=fixture.user_goal_id
        )
        run = run_attack(wanted, monitor=monitor, oracle=_oracle_for(goals, monitor))
        name, scripted = ATTACK_NAMES[fixture.case.id], fixture.scripted
        verdict, step = fixture.case.expected.verdict, deciding_step(fixture)
    report = AttackReport(
        attack_id=run.attack_id,
        name=name,
        monitor=choice,
        ok=run.ok,
        deferred=run.deferred,
        deciding_step=step,
        expected_verdict=verdict,
        checks=_checks(run, scripted),
        oracle=_recorded_oracle(run.record, goals, monitor),
        attacker_goal=goal_status(run.record, goals.attacker_goal_id),
        user_goal=goal_status(run.record, goals.user_goal_id),
    )
    return report, run.record
