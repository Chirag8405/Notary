"""The run socket: pluggable run sources, close codes and client commands."""

import itertools
import threading
from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketTestSession
from starlette.websockets import WebSocketDisconnect

from notary_core.models import Command, EndorsementDecisionCommand, Event
from notary_server.app import create_app
from notary_server.commands import CommandContext, CommandRouter
from notary_server.runner import scenario_names
from notary_server.sources import RunMode, RunRequest, RunSource
from notary_world.golden import COMMAND_ADAPTER, EVENT_ADAPTER, golden_streams, sample_commands

GOLDEN = golden_streams()["poisoned_bill.notary"]
RUN_ID = GOLDEN[0].run_id
GATE_TIMEOUT_SECONDS = 5
FRAME_MARKER = "frame-text-that-must-not-be-echoed"


def frame(event: Event) -> str:
    return EVENT_ADAPTER.dump_json(event).decode("utf-8")


def decision(run_id: str = RUN_ID) -> str:
    command = EndorsementDecisionCommand(
        type="endorsement_decision", run_id=run_id, endorsement_id="e1", decision="approve"
    )
    return COMMAND_ADAPTER.dump_json(command).decode("utf-8")


def drain(ws: WebSocketTestSession) -> tuple[list[str], WebSocketDisconnect]:
    """Read text frames until the server closes the socket."""
    frames: list[str] = []
    while True:
        try:
            frames.append(ws.receive_text())
        except WebSocketDisconnect as closed:
            return frames, closed


class FakeSource:
    def __init__(self, script: Callable[[RunRequest], Iterator[Event]]) -> None:
        self.requests: list[RunRequest] = []
        self._script = script

    def events(self, request: RunRequest) -> Iterator[Event]:
        self.requests.append(request)
        return self._script(request)


def fixed(events: tuple[Event, ...]) -> FakeSource:
    return FakeSource(lambda _request: iter(events))


def gated(gate: threading.Event, before: tuple[Event, ...], after: tuple[Event, ...]) -> FakeSource:
    """Yield `before`, wait for `gate`, then yield `after`."""

    def script(_request: RunRequest) -> Iterator[Event]:
        yield from before
        assert gate.wait(GATE_TIMEOUT_SECONDS)
        yield from after

    return FakeSource(script)


def app_client(source: RunSource, router: CommandRouter | None = None) -> TestClient:
    sources: dict[RunMode, RunSource] = {"golden": source}
    return TestClient(create_app(event_delay=0, sources=sources, router=router))


default_client = TestClient(create_app(event_delay=0))


@pytest.mark.invariant("I6")
def test_default_mode_is_golden_and_byte_identical() -> None:
    with default_client.websocket_connect("/ws/runs/poisoned_bill") as ws:
        frames, closed = drain(ws)
    assert frames == [frame(e) for e in GOLDEN]
    assert closed.code == 1000


@pytest.mark.invariant("I6")
def test_every_golden_name_still_streams() -> None:
    streams = golden_streams()
    for name in scenario_names():
        expected = streams.get(name) or streams[f"{name}.notary"]
        with default_client.websocket_connect(f"/ws/runs/{name}") as ws:
            frames, closed = drain(ws)
        assert frames == [frame(e) for e in expected]
        assert closed.code == 1000


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("lane", ["undefended", "classifier", "notary"])
def test_golden_mode_serves_the_requested_lane(lane: str) -> None:
    expected = golden_streams()[f"poisoned_bill.{lane}"]
    with default_client.websocket_connect(f"/ws/runs/poisoned_bill?lane={lane}&mode=golden") as ws:
        frames, closed = drain(ws)
    assert frames == [frame(e) for e in expected]
    assert closed.code == 1000
    started = EVENT_ADAPTER.validate_json(frames[0])
    assert started.type == "run_started"
    assert started.lane == lane
    assert started.run_id == f"run-poisoned_bill-{lane}"


@pytest.mark.invariant("I6")
def test_golden_lanes_differ_in_outcome() -> None:
    """The undefended lane pays the attacker; the notary lane stops at the card."""
    outcomes: dict[str, bool] = {}
    for lane in ("undefended", "notary"):
        with default_client.websocket_connect(f"/ws/runs/poisoned_bill?lane={lane}") as ws:
            frames, _closed = drain(ws)
        events = [EVENT_ADAPTER.validate_json(f) for f in frames]
        outcomes[lane] = any(
            e.type == "oracle_updated" and e.result.attacker_goal_reached for e in events
        )
    assert outcomes == {"undefended": True, "notary": False}


@pytest.mark.invariant("I6")
def test_golden_scenario_without_a_stream_for_the_lane_closes_4404() -> None:
    """`legitimate_bill` has only a NOTARY golden stream (#196); no other lane gets it."""
    with default_client.websocket_connect("/ws/runs/legitimate_bill?lane=undefended") as ws:
        frames, closed = drain(ws)
    assert frames == []
    assert (closed.code, closed.reason) == (4404, "unknown scenario")


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("query", ["lane=oops", "mode=oops", "lane=&mode="])
def test_invalid_lane_or_mode_closes_4400(query: str) -> None:
    with default_client.websocket_connect(f"/ws/runs/poisoned_bill?{query}") as ws:
        frames, closed = drain(ws)
    assert frames == []
    assert (closed.code, closed.reason) == (4400, "invalid run request")


@pytest.mark.invariant("I6")
def test_unknown_scenario_closes_4404() -> None:
    with default_client.websocket_connect("/ws/runs/nope") as ws:
        frames, closed = drain(ws)
    assert frames == []
    assert (closed.code, closed.reason) == (4404, "unknown scenario")


@pytest.mark.invariant("I6")
def test_unavailable_mode_closes_4501() -> None:
    with default_client.websocket_connect("/ws/runs/poisoned_bill?mode=live") as ws:
        frames, closed = drain(ws)
    assert frames == []
    assert (closed.code, closed.reason) == (4501, "mode not available")


@pytest.mark.invariant("I6")
def test_custom_source_is_streamed() -> None:
    client = app_client(fixed(GOLDEN[:3]))
    with client.websocket_connect("/ws/runs/anything") as ws:
        frames, closed = drain(ws)
    assert frames == [frame(e) for e in GOLDEN[:3]]
    assert closed.code == 1000


@pytest.mark.invariant("I6")
def test_source_receives_the_request() -> None:
    source = fixed(GOLDEN[:1])
    client = TestClient(create_app(event_delay=0, sources={"cassette": source}))
    with client.websocket_connect("/ws/runs/poisoned_bill?lane=classifier&mode=cassette") as ws:
        drain(ws)
    assert source.requests == [
        RunRequest(scenario="poisoned_bill", lane="classifier", mode="cassette")
    ]


@pytest.mark.invariant("I4")
def test_command_is_dispatched_while_streaming() -> None:
    gate = threading.Event()
    handled: list[tuple[Command, CommandContext]] = []

    def handler(command: Command, context: CommandContext) -> None:
        handled.append((command, context))
        gate.set()

    router = CommandRouter()
    router.register("endorsement_decision", handler)
    client = app_client(gated(gate, GOLDEN[:1], GOLDEN[1:2]), router)
    with client.websocket_connect("/ws/runs/poisoned_bill") as ws:
        try:
            assert ws.receive_text() == frame(GOLDEN[0])
            ws.send_text(decision())
            assert ws.receive_text() == frame(GOLDEN[1])
            frames, closed = drain(ws)
        finally:
            gate.set()
    assert frames == []
    assert closed.code == 1000
    assert handled == [
        (
            EndorsementDecisionCommand(
                type="endorsement_decision", run_id=RUN_ID, endorsement_id="e1", decision="approve"
            ),
            CommandContext(run_id=RUN_ID, lane="notary"),
        )
    ]


def close_after_command(
    text: str, router: CommandRouter | None = None, *, first_event: bool = True
) -> WebSocketDisconnect:
    """Send `text` to a source that blocks after (or before) its first event; return the close."""
    gate = threading.Event()
    source = gated(gate, GOLDEN[:1] if first_event else (), GOLDEN[1:2])
    client = app_client(source, router)
    with client.websocket_connect("/ws/runs/poisoned_bill") as ws:
        try:
            if first_event:
                ws.receive_text()
            ws.send_text(text)
            frames, closed = drain(ws)
        finally:
            gate.set()
    assert frames == []
    return closed


def router_with_handler(calls: list[Command]) -> CommandRouter:
    router = CommandRouter()
    router.register("endorsement_decision", lambda command, _context: calls.append(command))
    return router


@pytest.mark.invariant("I4")
@pytest.mark.parametrize(
    "text",
    [
        FRAME_MARKER,
        f'{{"type": "{FRAME_MARKER}"}}',
        f'{{"type": "endorsement_decision", "run_id": "{FRAME_MARKER}", "decision": "approve"}}',
    ],
    ids=["garbage", "unknown-type", "missing-field"],
)
def test_invalid_command_closes_4400(text: str) -> None:
    calls: list[Command] = []
    closed = close_after_command(text, router_with_handler(calls))
    assert (closed.code, closed.reason) == (4400, "invalid command")
    assert FRAME_MARKER not in closed.reason
    assert calls == []


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("command_type", ["hijacked_tool_call", "poison_world", "arena_start"])
def test_unsupported_command_closes_4422(command_type: str) -> None:
    command = sample_commands()[command_type]
    calls: list[Command] = []
    closed = close_after_command(
        COMMAND_ADAPTER.dump_json(command).decode("utf-8"), router_with_handler(calls)
    )
    assert (closed.code, closed.reason) == (4422, "command not supported on this socket")
    assert calls == []


@pytest.mark.invariant("I6")
def test_command_without_a_registered_handler_closes_4422() -> None:
    closed = close_after_command(decision())
    assert (closed.code, closed.reason) == (4422, "command not supported on this socket")


@pytest.mark.invariant("I4")
def test_command_for_another_run_closes_4409() -> None:
    calls: list[Command] = []
    closed = close_after_command(decision("run-of-someone-else"), router_with_handler(calls))
    assert (closed.code, closed.reason) == (4409, "command is for another run")
    assert calls == []


@pytest.mark.invariant("I4")
@pytest.mark.parametrize("command_type", ["endorsement_decision", "poison_world"])
def test_command_before_the_first_event_is_rejected(command_type: str) -> None:
    text = (
        decision()
        if command_type == "endorsement_decision"
        else COMMAND_ADAPTER.dump_json(sample_commands()[command_type]).decode("utf-8")
    )
    calls: list[Command] = []
    closed = close_after_command(text, router_with_handler(calls), first_event=False)
    assert (closed.code, closed.reason) == (4409, "run not started")
    assert calls == []


@pytest.mark.invariant("I6")
def test_client_disconnect_closes_the_source() -> None:
    closed = threading.Event()

    def script(_request: RunRequest) -> Iterator[Event]:
        try:
            yield from itertools.cycle(GOLDEN)
        finally:
            closed.set()

    client = TestClient(create_app(event_delay=0.01, sources={"golden": FakeSource(script)}))
    with client.websocket_connect("/ws/runs/poisoned_bill") as ws:
        ws.receive_text()
    assert closed.is_set()


@pytest.mark.invariant("I6")
def test_runs_modes_route() -> None:
    assert default_client.get("/runs/modes").json() == {"modes": ["golden"]}
    sources: dict[RunMode, RunSource] = {"golden": fixed(()), "cassette": fixed(())}
    client = TestClient(create_app(event_delay=0, sources=sources))
    assert client.get("/runs/modes").json() == {"modes": ["cassette", "golden"]}
    operation = default_client.get("/openapi.json").json()["paths"]["/runs/modes"]["get"]
    assert operation["operationId"] == "listRunModes"


@pytest.mark.invariant("I6")
def test_blocking_source_does_not_block_other_requests() -> None:
    gate = threading.Event()
    app = create_app(event_delay=0, sources={"golden": gated(gate, GOLDEN[:1], ())})
    with TestClient(app) as client, client.websocket_connect("/ws/runs/poisoned_bill") as ws:
        try:
            ws.receive_text()
            assert client.get("/health").json() == {"status": "ok"}
        finally:
            gate.set()
