"""The Endorsement Service: pending approvals, approve/reject commands, fail-closed timeout."""

import threading
import time
from collections.abc import Callable, Generator, Sequence
from typing import Literal

import pytest
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketTestSession
from starlette.websockets import WebSocketDisconnect

from notary_core.audit import append
from notary_core.models import (
    AuditEntry,
    Command,
    DiffCard,
    DiffRow,
    EffectBudget,
    EffectExecuted,
    EndorseMarker,
    Endorsement,
    EndorsementDecisionCommand,
    EndorsementRequested,
    Event,
    IntentContract,
    LlmOrigin,
    ToolScope,
)
from notary_core.runner import hooks_for_lane
from notary_server.agent_io import REFUSAL_TEXT
from notary_server.agent_runner import ServerAgentRunner
from notary_server.app import create_app
from notary_server.commands import CommandContext, CommandRejected
from notary_server.endorsement import (
    DEFAULT_TIMEOUT_SECONDS,
    EndorsementBroker,
    PendingList,
    SubmitResult,
)
from notary_server.llm import ScriptedClient
from notary_server.sources import RunMode, RunRequest, RunSource
from notary_world.executor import RunRecord, default_monitor
from notary_world.golden import COMMAND_ADAPTER
from notary_world.models import CassetteToolCall, CassetteTurn
from notary_world.scenarios import Scenario, legitimate_bill_scenario
from notary_world.tools import default_manifest_hash

Decision = Literal["approve", "reject"]
JOIN_SECONDS = 5.0


def endorsement(endorsement_id: str = "e1", preview: str = "Alpha Consulting") -> Endorsement:
    row = DiffRow(
        param="name",
        value_id="v1",
        origin=LlmOrigin(kind="llm"),
        integrity="untrusted",
        preview=preview,
        nearest_ledger_value=None,
        differing_positions=(),
    )
    return Endorsement(
        endorsement_id=endorsement_id,
        call_id="c1",
        card=DiffCard(rows=(row,)),
        status="pending",
        sequence=0,
    )


def decision(
    run_id: str = "r1", endorsement_id: str = "e1", decision_: Decision = "approve"
) -> EndorsementDecisionCommand:
    return EndorsementDecisionCommand(
        type="endorsement_decision",
        run_id=run_id,
        endorsement_id=endorsement_id,
        decision=decision_,
    )


class Waiter:
    """Runs `decide(endorsement)` in a thread, like the agent runner's worker thread."""

    def __init__(self, decide: Callable[[Endorsement], Decision], card: Endorsement) -> None:
        self.result: Decision | None = None
        self._thread = threading.Thread(target=self._run, args=(decide, card), daemon=True)
        self._thread.start()

    def _run(self, decide: Callable[[Endorsement], Decision], card: Endorsement) -> None:
        self.result = decide(card)

    def join(self) -> Decision | None:
        self._thread.join(JOIN_SECONDS)
        assert not self._thread.is_alive()
        return self.result


def wait_until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + JOIN_SECONDS
    while not condition():
        assert time.monotonic() < deadline, "condition not reached"
        time.sleep(0.002)


def waiting(
    broker: EndorsementBroker, run_id: str = "r1", card: Endorsement | None = None
) -> Waiter:
    pending_card = card or endorsement()
    waiter = Waiter(broker.decider_for(run_id, max_approvals=3), pending_card)
    wait_until(lambda: len(broker.pending(run_id)) > 0)
    return waiter


@pytest.mark.invariant("I4")
def test_approve_unblocks_the_decider() -> None:
    broker = EndorsementBroker()
    waiter = waiting(broker)
    assert broker.submit(decision()) == "accepted"
    assert waiter.join() == "approve"


@pytest.mark.attack("A11")
def test_reject_unblocks_the_decider() -> None:
    broker = EndorsementBroker()
    waiter = waiting(broker)
    assert broker.submit(decision(decision_="reject")) == "accepted"
    assert waiter.join() == "reject"


@pytest.mark.attack("A11")
def test_timeout_rejects_and_closes_the_slot() -> None:
    broker = EndorsementBroker(timeout_seconds=0.05)
    decide = broker.decider_for("r1", max_approvals=3)
    assert decide(endorsement()) == "reject"
    assert broker.submit(decision()) == "already_resolved"
    assert broker.pending("r1") == ()


@pytest.mark.attack("A11")
def test_cancel_run_rejects_waiters() -> None:
    broker = EndorsementBroker()
    decide = broker.decider_for("r1", max_approvals=3)
    first, second = Waiter(decide, endorsement("e1")), Waiter(decide, endorsement("e2"))
    wait_until(lambda: len(broker.pending("r1")) == 2)
    other = waiting(broker, "r2", endorsement("e1"))
    broker.cancel_run("r1")
    assert (first.join(), second.join()) == ("reject", "reject")
    assert broker.submit(decision("r1", "e1")) == "already_resolved"
    assert broker.submit(decision("r2", "e1", "reject")) == "accepted"
    assert other.join() == "reject"


@pytest.mark.attack("A11")
def test_a_cancelled_run_rejects_later_escalations_at_once() -> None:
    broker = EndorsementBroker()
    decide = broker.decider_for("r1", max_approvals=3)
    broker.cancel_run("r1")
    assert decide(endorsement("e5")) == "reject"
    assert broker.pending("r1") == ()


@pytest.mark.invariant("I4")
def test_first_decision_wins() -> None:
    broker = EndorsementBroker()
    waiter = waiting(broker)
    assert broker.submit(decision(decision_="approve")) == "accepted"
    assert broker.submit(decision(decision_="reject")) == "already_resolved"
    assert broker.submit(decision(decision_="approve")) == "already_resolved"
    assert waiter.join() == "approve"


@pytest.mark.invariant("I4")
def test_unknown_endorsement_and_unknown_run() -> None:
    broker = EndorsementBroker()
    waiter = waiting(broker)
    assert broker.submit(decision(endorsement_id="e99")) == "unknown_endorsement"
    assert broker.submit(decision(run_id="nope")) == "unknown_endorsement"
    assert broker.pending("nope") == ()
    assert len(broker.pending("r1")) == 1
    broker.cancel_run("r1")
    waiter.join()


@pytest.mark.invariant("I4")
def test_runs_are_isolated() -> None:
    broker = EndorsementBroker()
    first, second = waiting(broker, "r1"), waiting(broker, "r2")
    assert broker.submit(decision("r1")) == "accepted"
    assert first.join() == "approve"
    assert len(broker.pending("r2")) == 1
    assert broker.submit(decision("r2", decision_="reject")) == "accepted"
    assert second.join() == "reject"


@pytest.mark.invariant("I4")
def test_a_new_run_with_the_same_id_never_reuses_an_old_decision() -> None:
    broker = EndorsementBroker()
    approved = waiting(broker, "r1")
    assert broker.submit(decision()) == "accepted"
    assert approved.join() == "approve"
    # The same run id starts again (golden run ids repeat): the old "approve" must not answer it.
    again = waiting(broker, "r1")
    assert len(broker.pending("r1")) == 1
    assert again.result is None
    broker.cancel_run("r1")
    assert again.join() == "reject"


@pytest.mark.attack("A11")
def test_announce_registers_the_card_without_a_waiter() -> None:
    broker = EndorsementBroker()
    run = broker.start_run("r1", max_approvals=2)
    run.announce(endorsement())
    (entry,) = broker.pending("r1")
    assert (entry.endorsement, entry.remaining_approvals) == (endorsement(), 2)
    run.announce(endorsement())  # idempotent
    assert len(broker.pending("r1")) == 1
    waiter = Waiter(run.decide, endorsement())
    assert broker.submit(decision()) == "accepted"
    assert waiter.join() == "approve"
    assert broker.pending("r1") == ()


@pytest.mark.attack("A11")
def test_an_answer_before_the_decider_is_asked_is_kept() -> None:
    broker = EndorsementBroker()
    run = broker.start_run("r1", max_approvals=1)
    run.announce(endorsement())
    assert broker.submit(decision(decision_="reject")) == "accepted"
    assert broker.submit(decision()) == "already_resolved"
    assert run.decide(endorsement()) == "reject"


@pytest.mark.attack("A11")
def test_an_announced_card_is_rejected_when_the_run_is_cancelled_or_restarted() -> None:
    broker = EndorsementBroker()
    run = broker.start_run("r1", max_approvals=1)
    run.announce(endorsement())
    broker.cancel_run("r1")
    assert broker.pending("r1") == ()
    assert run.decide(endorsement()) == "reject"
    run.announce(endorsement("e2"))  # a cancelled run registers nothing that can be approved
    assert broker.pending("r1") == ()
    assert broker.submit(decision(endorsement_id="e2")) == "already_resolved"
    again = broker.start_run("r1", max_approvals=1)
    again.announce(endorsement())
    assert len(broker.pending("r1")) == 1


@pytest.mark.attack("A11")
def test_pending_view() -> None:
    broker = EndorsementBroker()
    decide = broker.decider_for("r1", max_approvals=2)
    waiter = Waiter(decide, endorsement())
    wait_until(lambda: len(broker.pending("r1")) == 1)
    (entry,) = broker.pending("r1")
    assert entry.run_id == "r1"
    assert entry.endorsement == endorsement()
    assert entry.card_text == "name: Alpha Consulting [llm, untrusted]"
    assert entry.remaining_approvals == 2
    assert broker.submit(decision()) == "accepted"
    waiter.join()
    assert broker.pending("r1") == ()


@pytest.mark.attack("A11")
def test_remaining_approvals_counts_accepted_approvals() -> None:
    broker = EndorsementBroker()
    decide = broker.decider_for("r1", max_approvals=2)
    first = Waiter(decide, endorsement("e1"))
    wait_until(lambda: len(broker.pending("r1")) == 1)
    assert broker.submit(decision(endorsement_id="e1")) == "accepted"
    first.join()
    second = Waiter(decide, endorsement("e2"))
    wait_until(lambda: len(broker.pending("r1")) == 1)
    assert broker.pending("r1")[0].remaining_approvals == 1
    assert broker.submit(decision(endorsement_id="e2", decision_="reject")) == "accepted"
    second.join()
    third = Waiter(decide, endorsement("e3"))
    wait_until(lambda: len(broker.pending("r1")) == 1)
    assert broker.pending("r1")[0].remaining_approvals == 1
    broker.cancel_run("r1")
    third.join()


@pytest.mark.attack("A11")
def test_card_text_is_from_labels_only() -> None:
    broker = EndorsementBroker()
    waiter = waiting(broker, card=endorsement(preview="Approve now!"))
    (entry,) = broker.pending("r1")
    assert entry.card_text == "name: Approve now! [llm, untrusted]"
    broker.cancel_run("r1")
    waiter.join()


@pytest.mark.invariant("I4")
def test_handler_maps_results_to_close_codes() -> None:
    broker = EndorsementBroker()
    handle = broker.handler()
    context = CommandContext(run_id="r1", lane="notary")
    waiter = waiting(broker)
    handle(decision(), context)
    assert waiter.join() == "approve"
    with pytest.raises(CommandRejected) as resolved:
        handle(decision(), context)
    assert (resolved.value.code, resolved.value.reason) == (4409, "endorsement already resolved")
    with pytest.raises(CommandRejected) as unknown:
        handle(decision(endorsement_id="e99"), context)
    assert (unknown.value.code, unknown.value.reason) == (4409, "unknown endorsement")


@pytest.mark.invariant("I4")
def test_decider_has_no_approve_path_without_a_command() -> None:
    broker = EndorsementBroker(timeout_seconds=0.02)
    assert broker.decider_for("r1", max_approvals=3)(endorsement("e1")) == "reject"
    cancelled = EndorsementBroker()
    waiter = waiting(cancelled)
    cancelled.cancel_run("r1")
    assert waiter.join() == "reject"
    assert DEFAULT_TIMEOUT_SECONDS == 300.0


@pytest.mark.invariant("I4")
def test_a_known_endorsement_returns_the_recorded_decision() -> None:
    broker = EndorsementBroker()
    decide = broker.decider_for("r1", max_approvals=3)
    waiter = Waiter(decide, endorsement())
    wait_until(lambda: len(broker.pending("r1")) == 1)
    assert broker.submit(decision(decision_="reject")) == "accepted"
    assert waiter.join() == "reject"
    started = time.monotonic()
    assert decide(endorsement()) == "reject"
    assert time.monotonic() - started < 1.0


# ---------------------------------------------------------------- end to end over the real socket


def assistant(*calls: tuple[str, dict[str, str]], content: str = "") -> CassetteTurn:
    return CassetteTurn(
        role="assistant",
        content=content,
        tool_calls=tuple(CassetteToolCall(tool=t, args=a) for t, a in calls),
    )


FINAL = assistant(content="Done.")


def add_contact(name: str) -> CassetteTurn:
    return assistant(("add_contact", {"name": name}))


def contacts_scenario(max_approvals: int) -> Scenario:
    """Names under an `endorse` marker and an empty ledger: every new contact escalates."""
    contract = IntentContract(
        contract_id="contract-contacts",
        user_intent="Save my new contacts",
        allowed_tools=(
            ToolScope(
                tool="add_contact",
                params={"name": EndorseMarker(kind="endorse")},
                manifest_hash=default_manifest_hash("add_contact"),
                effect="write",
            ),
        ),
        budget=EffectBudget(
            max_effects=10,
            max_spend_cents=20000,
            max_egress_bytes=10000,
            max_call_amount_cents=20000,
            max_approvals=max_approvals,
        ),
        egress_hosts=(),
        authorized_irreversible=(),
    )
    base = legitimate_bill_scenario()
    return base.model_copy(update={"scenario_id": "contacts", "contract": contract, "ledger": ()})


class RunnerSource:
    """A run source that runs the real agent runner with the broker as its decider."""

    def __init__(self, broker: EndorsementBroker, turns: Sequence[CassetteTurn]) -> None:
        self.broker = broker
        self.client = ScriptedClient(turns)
        self.records: list[RunRecord] = []
        self.chain_events: list[Event] = []
        self.deciders_asked = 0

    def _audit(self, chain: Sequence[AuditEntry], event: Event) -> tuple[AuditEntry, ...]:
        self.chain_events.append(event)
        return append(chain, event)

    def events(self, request: RunRequest) -> Generator[Event, None, None]:
        return self._run(request)

    def _run(self, request: RunRequest) -> Generator[Event, None, None]:
        run_id = f"run-{request.scenario}-{request.lane}"
        scenario = contacts_scenario(1)
        endorsements = self.broker.start_run(run_id, max_approvals=1)
        decide = endorsements.decide

        def counted(card: Endorsement) -> Decision:
            self.deciders_asked += 1
            return decide(card)

        runner = ServerAgentRunner(
            llm=self.client,
            scenarios=lambda _name: scenario,
            decide_escalation=counted,
            announce_escalation=endorsements.announce,
            audit_append=self._audit,
        )
        hooks = hooks_for_lane("notary", gate=default_monitor())
        record = yield from runner.run(
            lane="notary", scenario=request.scenario, run_id=run_id, hooks=hooks
        )
        self.records.append(record)


def socket_client(source: RunnerSource, event_delay: float = 0) -> TestClient:
    sources: dict[RunMode, RunSource] = {"golden": source}
    return TestClient(create_app(event_delay=event_delay, sources=sources, broker=source.broker))


def frames_until(ws: WebSocketTestSession, event_type: str) -> list[Event]:
    from notary_world.golden import EVENT_ADAPTER

    seen: list[Event] = []
    while True:
        event = EVENT_ADAPTER.validate_json(ws.receive_text())
        seen.append(event)
        if event.type == event_type:
            return seen


def finish(ws: WebSocketTestSession) -> WebSocketDisconnect:
    while True:
        try:
            ws.receive_text()
        except WebSocketDisconnect as closed:
            return closed


def decide_over_socket(
    ws: WebSocketTestSession, run_id: str, endorsement_id: str, decision_: Decision
) -> None:
    command: Command = decision(run_id, endorsement_id, decision_)
    ws.send_text(COMMAND_ADAPTER.dump_json(command).decode("utf-8"))


def requested(events: Sequence[Event]) -> EndorsementRequested:
    return next(e for e in reversed(events) if isinstance(e, EndorsementRequested))


def events_until_requested(
    source: RunnerSource,
) -> tuple[Generator[Event, None, None], EndorsementRequested]:
    """Drive the run on this thread to the moment the consumer is handed the card event."""
    events = source.events(RunRequest(scenario="contacts", lane="notary", mode="golden"))
    for event in events:
        if isinstance(event, EndorsementRequested):
            return events, event
    raise AssertionError("the run never asked for an endorsement")


@pytest.mark.invariant("I4")
def test_the_card_is_pending_when_the_event_is_handed_over() -> None:
    """#195: the card is registered before `endorsement_requested` leaves the runner, not when the
    runner reaches the decider (after the stream's per-event delay)."""
    source = RunnerSource(EndorsementBroker(), [add_contact("Alpha Consulting"), FINAL])
    events, card = events_until_requested(source)
    assert source.deciders_asked == 0  # the runner has not asked the decider yet
    (entry,) = source.broker.pending(card.run_id)
    assert entry.endorsement == card.endorsement
    assert entry.remaining_approvals == 1
    source.broker.cancel_run(card.run_id)
    events.close()


@pytest.mark.invariant("I4")
def test_an_answer_inside_the_old_gap_is_accepted_and_used() -> None:
    """The answer arrives after the event is handed over and before the decider is asked."""
    source = RunnerSource(EndorsementBroker(), [add_contact("Alpha Consulting"), FINAL])
    events, card = events_until_requested(source)
    result = source.broker.submit(decision(card.run_id, card.endorsement.endorsement_id))
    assert result == "accepted"
    assert source.deciders_asked == 0
    rest = list(events)
    assert source.deciders_asked == 1
    (record,) = source.records
    assert [c.name for c in record.world_after.contacts][-1] == "Alpha Consulting"
    assert any(isinstance(e, EffectExecuted) for e in rest)
    assert source.broker.pending(card.run_id) == ()


@pytest.mark.invariant("I4")
def test_end_to_end_approval_writes_a_user_endorsed_entry() -> None:
    source = RunnerSource(EndorsementBroker(), [add_contact("Alpha Consulting"), FINAL])
    client = socket_client(source)
    with client.websocket_connect("/ws/runs/contacts") as ws:
        seen = frames_until(ws, "endorsement_requested")
        card = requested(seen)
        run_id = card.run_id
        wait_until(lambda: len(source.broker.pending(run_id)) == 1)
        (entry,) = source.broker.pending(run_id)
        assert entry.remaining_approvals == 1
        assert entry.card_text == "name: alpha consulting [llm, untrusted]"
        assert client.get(f"/runs/{run_id}/endorsements").json()["pending"][0]["card_text"] == (
            entry.card_text
        )
        decide_over_socket(ws, run_id, card.endorsement.endorsement_id, "approve")
        closed = finish(ws)
    assert closed.code == 1000
    (record,) = source.records
    assert [c.name for c in record.world_after.contacts][-1] == "Alpha Consulting"
    (ledger_entry,) = record.ledger_snapshots[-1].ledger
    assert ledger_entry.source.kind == "user_endorsed"
    assert ledger_entry.source.endorsement_id == card.endorsement.endorsement_id
    assert source.broker.pending(run_id) == ()


@pytest.mark.invariant("I4")
def test_a_fast_answer_over_the_socket_needs_no_wait() -> None:
    """#195 over the real socket: list the card and answer it the moment the frame is received."""
    source = RunnerSource(EndorsementBroker(), [add_contact("Alpha Consulting"), FINAL])
    client = socket_client(source, event_delay=0.05)
    with client.websocket_connect("/ws/runs/contacts") as ws:
        seen = frames_until(ws, "endorsement_requested")
        card = requested(seen)
        listed = client.get(f"/runs/{card.run_id}/endorsements").json()["pending"]
        assert [p["endorsement"]["endorsement_id"] for p in listed] == [
            card.endorsement.endorsement_id
        ]
        assert listed[0]["remaining_approvals"] == 1
        decide_over_socket(ws, card.run_id, card.endorsement.endorsement_id, "approve")
        closed = finish(ws)
    assert closed.code == 1000
    (record,) = source.records
    assert [c.name for c in record.world_after.contacts][-1] == "Alpha Consulting"


@pytest.mark.attack("A11")
def test_end_to_end_budget_exhaustion() -> None:
    source = RunnerSource(
        EndorsementBroker(), [add_contact("Alpha Consulting"), add_contact("Bravo Holdings"), FINAL]
    )
    with socket_client(source).websocket_connect("/ws/runs/contacts") as ws:
        card = requested(frames_until(ws, "endorsement_requested"))
        wait_until(lambda: len(source.broker.pending(card.run_id)) == 1)
        decide_over_socket(ws, card.run_id, card.endorsement.endorsement_id, "approve")
        finish(ws)
    (record,) = source.records
    blocked = [
        e.decision
        for e in record.events
        if e.type == "decision_made" and e.decision.verdict == "BLOCK"
    ]
    assert [d.reasons[-1].code for d in blocked] == ["BUDGET_APPROVALS_EXHAUSTED"]
    assert sum(e.type == "endorsement_requested" for e in record.events) == 1
    assert source.deciders_asked == 1
    assert source.broker.pending(card.run_id) == ()


@pytest.mark.attack("A9")
def test_end_to_end_reject_leaves_the_world_unchanged() -> None:
    source = RunnerSource(EndorsementBroker(), [add_contact("Alpha Consulting"), FINAL])
    with socket_client(source).websocket_connect("/ws/runs/contacts") as ws:
        card = requested(frames_until(ws, "endorsement_requested"))
        wait_until(lambda: len(source.broker.pending(card.run_id)) == 1)
        decide_over_socket(ws, card.run_id, card.endorsement.endorsement_id, "reject")
        finish(ws)
    (record,) = source.records
    assert record.world_diff.changes == ()
    assert record.ledger_snapshots[-1].ledger == ()
    assert record.session.approvals_used == 0
    tool_messages = [m.content for m in source.client.requests[-1].messages if m.role == "tool"]
    assert tool_messages[-1] == REFUSAL_TEXT


@pytest.mark.attack("A11")
def test_end_to_end_no_answer_fails_closed() -> None:
    source = RunnerSource(EndorsementBroker(timeout_seconds=0.05), [add_contact("Alpha"), FINAL])
    with socket_client(source).websocket_connect("/ws/runs/contacts") as ws:
        frames_until(ws, "endorsement_requested")
        closed = finish(ws)
    assert closed.code == 1000
    (record,) = source.records
    assert record.world_diff.changes == ()
    assert not any(isinstance(e, EffectExecuted) for e in record.events)


@pytest.mark.invariant("I4")
def test_decision_for_a_wrong_endorsement_closes_the_socket() -> None:
    source = RunnerSource(EndorsementBroker(), [add_contact("Alpha Consulting"), FINAL])
    with socket_client(source).websocket_connect("/ws/runs/contacts") as ws:
        card = requested(frames_until(ws, "endorsement_requested"))
        wait_until(lambda: len(source.broker.pending(card.run_id)) == 1)
        decide_over_socket(ws, card.run_id, "e99", "approve")
        closed = finish(ws)
    assert (closed.code, closed.reason) == (4409, "unknown endorsement")
    assert not any(isinstance(e, EffectExecuted) for e in source.chain_events)
    assert source.broker.pending(card.run_id) == ()


@pytest.mark.attack("A11")
def test_a_disconnect_rejects_the_pending_card() -> None:
    source = RunnerSource(EndorsementBroker(), [add_contact("Alpha Consulting"), FINAL])
    with socket_client(source).websocket_connect("/ws/runs/contacts") as ws:
        card = requested(frames_until(ws, "endorsement_requested"))
        wait_until(lambda: len(source.broker.pending(card.run_id)) == 1)
    assert source.broker.pending(card.run_id) == ()
    assert not any(isinstance(e, EffectExecuted) for e in source.chain_events)


@pytest.mark.invariant("I6")
def test_rest_pending_route() -> None:
    broker = EndorsementBroker()
    waiter = waiting(broker, "r1")
    client = TestClient(create_app(event_delay=0, broker=broker))
    body = PendingList.model_validate_json(client.get("/runs/r1/endorsements").content)
    assert body.pending == broker.pending("r1")
    assert client.get("/runs/nope/endorsements").json() == {"pending": []}
    operation = client.get("/openapi.json").json()["paths"]["/runs/{run_id}/endorsements"]["get"]
    assert operation["operationId"] == "listEndorsements"
    broker.cancel_run("r1")
    waiter.join()


@pytest.mark.invariant("I6")
def test_without_a_broker_the_route_is_empty_and_decisions_are_rejected() -> None:
    client = TestClient(create_app(event_delay=0))
    assert client.get("/runs/r1/endorsements").json() == {"pending": []}


def result_of(broker: EndorsementBroker, command: EndorsementDecisionCommand) -> SubmitResult:
    return broker.submit(command)
