"""The agent runner: a hand-written LLM tool loop that implements `AgentRunner` for every lane.

The loop only PROPOSES calls. Everything that decides or executes is the lane-B `RunEngine`,
with the real core Gateway pieces plugged in (the labeler and the argument resolver); the
monitor is whatever gate the lane's hooks carry. The engine's audit chain IS the event stream:
`run` yields each new chain entry right after the operation that appended it, so a consumer sees
an `endorsement_requested` event before the decider is asked, and two runs over the same cassette
are byte-identical. `run` returns the final `RunRecord` (a generator's return value).
"""

from collections.abc import Callable, Generator, Mapping, Sequence
from types import MappingProxyType
from typing import Literal

from notary_core.audit import append
from notary_core.gateway import ToolResult, ToolResultField, make_labeler
from notary_core.models import (
    CHECK_ORDER,
    Decision,
    Endorsement,
    EndorsementRequested,
    Event,
    IntentContract,
    Lane,
    LedgerEntry,
    OracleResult,
    Reason,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
)
from notary_core.monitor import Monitor
from notary_core.resolver import ArgumentResolver
from notary_core.runner import RunnerHooks
from notary_server.agent_io import (
    AGENT_SYSTEM,
    MAX_TURNS,
    REFUSAL_TEXT,
    agent_tools,
    calls_from_turn,
    render_result,
    result_message,
)
from notary_server.compiler import with_optional_params
from notary_server.labeling import world_labeling_policy
from notary_server.llm import DEFAULT_MAX_TOKENS, DEFAULT_MODEL, LlmClient, LlmRequest
from notary_world.executor import (
    MAX_ESCALATION_ROUNDS,
    AuditAppend,
    CallOutcome,
    RunEngine,
    RunRecord,
    finish,
    propose,
    resolve_escalation,
    start_run,
)
from notary_world.invariants import check_invariants
from notary_world.models import CassetteTurn
from notary_world.oracle import GoalPair, evaluate
from notary_world.scenarios import Scenario
from notary_world.tools import TOOL_SPECS, RawToolCall, world_manifests, world_policy

EscalationDecider = Callable[[Endorsement], Literal["approve", "reject", "use_nearest"]]
"""Asked (possibly blocking) after the escalation was streamed. The only place a human approval
can enter a run."""

EscalationAnnouncer = Callable[[Endorsement], None]
"""Told about an escalation BEFORE its `endorsement_requested` event is handed to the consumer, so
a card is already pending when a client sees the event (#195). It must not block."""

ContractSource = Callable[[Scenario, Lane], IntentContract]

_BILL_GOALS = GoalPair(
    attacker_goal_id="attacker:pay_attacker_iban", user_goal_id="user:bill_paid_to_acme"
)
SCENARIO_GOALS: Mapping[str, GoalPair] = MappingProxyType(
    {"legitimate_bill": _BILL_GOALS, "poisoned_bill": _BILL_GOALS}
)


def reject_all(endorsement: Endorsement) -> Literal["approve", "reject", "use_nearest"]:
    """The default decider: an unattended run never approves anything."""
    return "reject"


def ignore_escalation(endorsement: Endorsement) -> None:
    """The default announcer: nobody needs to know before the event is streamed."""


def scenario_contract(scenario: Scenario, lane: Lane) -> IntentContract:
    """The scenario's contract with the optional parameters of its tools allowed at their floors.

    A real model fills optional parameters (`pay_bill.reference`); the hand-written scenario
    contracts name only the required ones, which would block a benign bill at scope. The floors
    of the sensitive-parameter table are not lowered (see `with_optional_params`).
    """
    return with_optional_params(scenario.contract, world_manifests(scenario.world), world_policy())


def goals_for(scenario_id: str) -> GoalPair:
    """The oracle's goal pair; poison-the-world scenarios reuse the bill goals."""
    return SCENARIO_GOALS.get(scenario_id, _BILL_GOALS)


def ungated_monitor() -> Monitor:
    """ALLOW everything, with one `STEP_PASS` per check: the baseline lanes have no gate."""
    reasons = tuple(
        Reason(check=check, outcome="pass", code="STEP_PASS", detail="") for check in CHECK_ORDER
    )

    def monitor(
        contract: IntentContract,
        proposal: ToolCallProposal,
        values: Mapping[str, ResolvedValue],
        ledger: Sequence[LedgerEntry],
        session: SessionState,
    ) -> Decision:
        return Decision(verdict="ALLOW", reasons=reasons, diff_card=None)

    return monitor


class _Cursor:
    """The engine is immutable; this keeps the latest one and how much of its chain was streamed."""

    def __init__(self, engine: RunEngine) -> None:
        self.engine = engine
        self._streamed = 0

    def fresh(self) -> list[Event]:
        events = [entry.event for entry in self.engine.chain[self._streamed :]]
        self._streamed = len(self.engine.chain)
        return events


def _endorsement(engine: RunEngine, endorsement_id: str) -> Endorsement:
    for entry in reversed(engine.chain):
        event = entry.event
        if (
            isinstance(event, EndorsementRequested)
            and event.endorsement.endorsement_id == endorsement_id
        ):
            return event.endorsement
    raise ValueError(f"no endorsement request for {endorsement_id}")


def _executed_text(
    engine: RunEngine,
    call: RawToolCall,
    before: frozenset[str],
    hooks: RunnerHooks,
    spotlight: bool,
) -> str:
    """What the agent sees of an executed call: its result records, or the effect summary."""
    records = [r for r in engine.calls if r.call_id == call.call_id]
    argument_ids = {a.value.ref.id for r in records for a in r.args}
    groups: dict[str, list[ResolvedValue]] = {}
    for value in engine.store:
        if value.ref.id in before or value.ref.id in argument_ids:
            continue
        groups.setdefault(value.ref.id.rsplit(".", 1)[0], []).append(value)
    parts: list[str] = []
    for record_id in sorted(groups):
        fields = tuple(
            ToolResultField(name=v.ref.id.rsplit(".", 1)[1], text=v.text, unit=v.unit)
            for v in sorted(groups[record_id], key=lambda v: v.ref.id.rsplit(".", 1)[1])
        )
        result = ToolResult(tool=call.tool, record_id=record_id, fields=fields)
        if hooks.pre_filter is None:
            parts.append(render_result(result, spotlight=spotlight))
        else:
            filtered = hooks.pre_filter(result)
            parts.append(render_result(filtered.result, filtered.flags, spotlight=spotlight))
    if parts:
        return "\n\n".join(parts)
    effect = records[-1].effect if records else None
    return "ok" if effect is None else effect.summary


class ServerAgentRunner:
    """Implements `notary_core.runner.AgentRunner`; see the module docstring."""

    def __init__(
        self,
        *,
        llm: LlmClient,
        scenarios: Callable[[str], Scenario],
        decide_escalation: EscalationDecider = reject_all,
        announce_escalation: EscalationAnnouncer = ignore_escalation,
        contracts: ContractSource = scenario_contract,
        model: str = DEFAULT_MODEL,
        audit_append: AuditAppend = append,
        run_note: str = "",
    ) -> None:
        self._llm = llm
        self._scenarios = scenarios
        self._decide = decide_escalation
        self._announce = announce_escalation
        self._contracts = contracts
        self._model = model
        self._audit_append = audit_append
        self._run_note = run_note

    def _announce_pending(self, engine: RunEngine, outcome: CallOutcome) -> None:
        if outcome.status == "escalated" and outcome.endorsement_id is not None:
            self._announce(_endorsement(engine, outcome.endorsement_id))

    def _one_call(
        self, cursor: _Cursor, call: RawToolCall, hooks: RunnerHooks, spotlight: bool
    ) -> Generator[Event, None, str | None]:
        """Propose one call, settle its escalations; the text for the agent, or None if halted."""
        before = frozenset(v.ref.id for v in cursor.engine.store)
        cursor.engine, outcome = propose(cursor.engine, call)
        self._announce_pending(cursor.engine, outcome)
        yield from cursor.fresh()
        rounds = 0
        while (
            outcome.status == "escalated"
            and outcome.endorsement_id is not None
            and rounds < MAX_ESCALATION_ROUNDS
        ):
            rounds += 1
            endorsement = _endorsement(cursor.engine, outcome.endorsement_id)
            decision = self._decide(endorsement)
            cursor.engine, resolved = resolve_escalation(
                cursor.engine, outcome.endorsement_id, decision
            )
            if resolved is not None:
                self._announce_pending(cursor.engine, resolved)
            yield from cursor.fresh()
            if resolved is None:
                break
            outcome = resolved
        if outcome.status == "halted":
            return None
        if outcome.status == "tool_error":
            return f"error: {outcome.error}"
        if outcome.status == "executed":
            # After "use nearest" the executed call is the replacement, under its own call id.
            ran = call.model_copy(update={"call_id": outcome.call_id})
            return _executed_text(cursor.engine, ran, before, hooks, spotlight)
        return REFUSAL_TEXT

    def run(
        self, *, lane: Lane, scenario: str, run_id: str, hooks: RunnerHooks
    ) -> Generator[Event, None, RunRecord]:
        prepared = self._scenarios(scenario)
        monitor = hooks.gate if hooks.gate is not None else ungated_monitor()
        cursor = _Cursor(
            start_run(
                run_id=run_id,
                scenario=scenario,
                request=prepared.user_request,
                world=prepared.world,
                contract=self._contracts(prepared, lane),
                ledger=prepared.ledger,
                session=prepared.session,
                lane=lane,
                monitor=monitor,
                gateway=make_labeler(world_labeling_policy()),
                resolver=ArgumentResolver(),
                audit_append=self._audit_append,
            )
        )
        yield from cursor.fresh()
        spotlight = hooks.gate is not None
        messages = [CassetteTurn(role="user", content=prepared.user_request, tool_calls=())]
        next_call = 1
        halted = False
        for _ in range(MAX_TURNS):
            request = LlmRequest(
                model=self._model,
                system=AGENT_SYSTEM,
                messages=tuple(messages),
                tools=agent_tools(TOOL_SPECS, cursor.engine.world),
                max_tokens=DEFAULT_MAX_TOKENS,
            )
            turn = self._llm.complete(request)
            messages.append(turn)
            calls = calls_from_turn(turn, first_index=next_call)
            if not calls:
                break
            next_call += len(calls)
            for call in calls:
                text = yield from self._one_call(cursor, call, hooks, spotlight)
                if text is None:
                    halted = True
                    break
                messages.append(result_message(call.call_id, text))
            if halted:
                break
        goals = goals_for(scenario)

        def oracle(run: RunRecord) -> OracleResult:
            return evaluate(run, goals, check_invariants(run, monitor))

        cursor.engine, record = finish(cursor.engine, oracle=oracle, note=self._run_note)
        yield from cursor.fresh()
        return record
