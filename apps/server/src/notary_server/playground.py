"""Judge playground: poison the world and the attack library (REST, synchronous)."""

from collections.abc import Callable, Iterator

from notary_core.models import (
    Event,
    ExpectedOutcome,
    Lane,
    NotaryModel,
    OracleResult,
    OracleUpdated,
    PoisonWorldCommand,
)
from notary_core.monitor import Monitor
from notary_world.attacks import (
    ALL_CONTROLS,
    ATTACK_NAMES,
    AttackNotFoundError,
    AttackRun,
    get_attack,
    get_control,
    run_attack,
    run_control,
)
from notary_world.executor import OracleFn, RunRecord, default_monitor
from notary_world.invariants import check_invariants
from notary_world.models import ScriptedCall
from notary_world.oracle import GoalPair, evaluate
from notary_world.poison import PoisonError
from notary_world.scenarios import Scenario, golden_run_id, scenario_from_command

LaneRunner = Callable[[Scenario, Lane, str], Iterator[Event]]
"""(scenario, lane, run id) -> the events of that run. The agent runner (P3b) provides it."""

MAX_PAYLOAD_CHARS: int = 2000

CONTROL_ATTACKER_GOAL = "attacker:pay_attacker_iban"
"""A benign control is judged against the attacker goal of the poisoned bill."""


class LaneRun(NotaryModel):
    lane: Lane
    run_id: str
    events: tuple[Event, ...]
    attacker_goal_reached: bool | None
    """From the last `oracle_updated` event; None if the stream has none."""
    user_goal_achieved: bool | None


class PoisonResponse(NotaryModel):
    scenario_id: str
    runs: tuple[LaneRun, ...]


class CheckSummary(NotaryModel):
    call_id: str
    tool: str
    expected: ExpectedOutcome
    actual: ExpectedOutcome | None
    matches: bool


class AttackRunResponse(NotaryModel):
    attack_id: str
    name: str
    ok: bool
    deferred: bool
    checks: tuple[CheckSummary, ...]
    oracle: OracleResult
    events: tuple[Event, ...]


class PlaygroundError(Exception):
    """A request the playground refuses; `status` and `detail` become the HTTP response."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def last_oracle_result(events: tuple[Event, ...]) -> OracleResult | None:
    return next((e.result for e in reversed(events) if isinstance(e, OracleUpdated)), None)


def attack_run_response(
    run: AttackRun,
    name: str,
    scripted: tuple[ScriptedCall, ...],
    oracle: OracleResult,
) -> AttackRunResponse:
    """The API view of an attack run. Every check is reported as the real monitor decided it."""
    tools = {call.call_id: call.tool for call in scripted}
    return AttackRunResponse(
        attack_id=run.attack_id,
        name=name,
        ok=run.ok,
        deferred=run.deferred,
        checks=tuple(
            CheckSummary(
                call_id=check.call_id,
                tool=tools[check.call_id],
                expected=check.expected,
                actual=check.actual,
                matches=check.matches,
            )
            for check in run.checks
        ),
        oracle=oracle,
        events=run.record.events,
    )


def _oracle_for(goals: GoalPair, monitor: Monitor) -> OracleFn:
    def oracle(run: RunRecord) -> OracleResult:
        return evaluate(run, goals, check_invariants(run, monitor))

    return oracle


class PlaygroundService:
    def __init__(self, lane_runner: LaneRunner | None) -> None:
        self._lane_runner = lane_runner

    def poison(self, command: PoisonWorldCommand) -> PoisonResponse:
        if len(command.payload) > MAX_PAYLOAD_CHARS:
            raise PlaygroundError(422, "payload too long")
        if not command.lanes or len(set(command.lanes)) != len(command.lanes):
            raise PlaygroundError(422, "lanes must be a non-empty list of distinct lanes")
        try:
            scenario = scenario_from_command(command)
        except PoisonError as error:
            raise PlaygroundError(422, str(error)) from None
        if self._lane_runner is None:
            raise PlaygroundError(501, "lane runner not configured")
        runs: list[LaneRun] = []
        for lane in command.lanes:
            run_id = golden_run_id(command.scenario, lane)
            events = tuple(self._lane_runner(scenario, lane, run_id))
            result = last_oracle_result(events)
            runs.append(
                LaneRun(
                    lane=lane,
                    run_id=run_id,
                    events=events,
                    attacker_goal_reached=None if result is None else result.attacker_goal_reached,
                    user_goal_achieved=None if result is None else result.user_goal_achieved,
                )
            )
        return PoisonResponse(scenario_id=scenario.scenario_id, runs=tuple(runs))

    def run_attack(self, attack_id: str) -> AttackRunResponse:
        """Replay an attack (A1-A14) or control (B1-B4) through the real monitor."""
        wanted = attack_id.upper()
        monitor = default_monitor()
        try:
            if wanted in {control.control_id for control in ALL_CONTROLS}:
                control = get_control(wanted)
                goals = GoalPair(
                    attacker_goal_id=CONTROL_ATTACKER_GOAL, user_goal_id=control.user_goal_id
                )
                run = run_control(wanted, monitor=monitor, oracle=_oracle_for(goals, monitor))
                name, scripted = control.title, control.scripted
            else:
                fixture = get_attack(wanted)
                goals = GoalPair(
                    attacker_goal_id=fixture.attacker_goal_id, user_goal_id=fixture.user_goal_id
                )
                run = run_attack(wanted, monitor=monitor, oracle=_oracle_for(goals, monitor))
                name, scripted = ATTACK_NAMES[fixture.case.id], fixture.scripted
        except AttackNotFoundError:
            raise PlaygroundError(404, "unknown attack id") from None
        oracle = last_oracle_result(run.record.events)
        if oracle is None:  # the run halted before it logged the oracle result
            oracle = _oracle_for(goals, monitor)(run.record)
        return attack_run_response(run, name, scripted, oracle)
