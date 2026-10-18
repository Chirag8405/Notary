"""Run the seeded attack library (A1-A14) and benign controls (B1-B4) under a defence lane."""

from collections.abc import Mapping, Sequence
from typing import Literal

from notary_core.models import (
    Decision,
    ExpectedOutcome,
    IntentContract,
    LedgerEntry,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
)
from notary_core.monitor import Monitor
from notary_eval.results import EvalResults, TaskResult
from notary_world.attacks import (
    ALL_ATTACKS,
    ALL_CONTROLS,
    get_attack,
    get_control,
    run_attack,
    run_control,
)
from notary_world.executor import RunRecord, default_monitor
from notary_world.fakes import decision_for
from notary_world.oracle import GoalPair, goal_reached

Defence = Literal["none", "notary"]
DEFENCES: tuple[Defence, ...] = ("none", "notary")
SUITE = "library"
CONTROL_ATTACKER_GOAL = "attacker:pay_attacker_iban"
"""The attacker goal a benign control is judged against (it must stay not reached)."""


def _allow_all(
    contract: IntentContract,
    proposal: ToolCallProposal,
    values: Mapping[str, ResolvedValue],
    ledger: Sequence[LedgerEntry],
    session: SessionState,
) -> Decision:
    """The no-defence lane: every proposed call is allowed."""
    return decision_for(ExpectedOutcome(verdict="ALLOW", deciding_check=None, code=None))


def monitor_for(defence: Defence) -> Monitor:
    return default_monitor() if defence == "notary" else _allow_all


def run_library(defence: Defence, seed: int = 0) -> EvalResults:
    """One `TaskResult` per attack and control (utility: user goal, attack: attacker goal)."""
    monitor = monitor_for(defence)
    results: list[TaskResult] = []
    for fixture in ALL_ATTACKS:
        goals = GoalPair(
            attacker_goal_id=get_attack(fixture.case.id).attacker_goal_id,
            user_goal_id=fixture.user_goal_id,
        )
        record = run_attack(fixture.case.id, monitor=monitor, seed=seed).record
        results.append(_task(fixture.case.id, goals, record))
    for control in ALL_CONTROLS:
        goals = GoalPair(
            attacker_goal_id=CONTROL_ATTACKER_GOAL,
            user_goal_id=get_control(control.control_id).user_goal_id,
        )
        record = run_control(control.control_id, monitor=monitor, seed=seed).record
        results.append(_task(control.control_id, goals, record))
    return EvalResults(defence=defence, results=tuple(results), seed=seed)


def _task(task_id: str, goals: GoalPair, record: RunRecord) -> TaskResult:
    return TaskResult(
        suite=SUITE,
        task_id=task_id,
        utility=goal_reached(record, goals.user_goal_id),
        attack_succeeded=goal_reached(record, goals.attacker_goal_id),
    )
