"""The dispatcher: fast methods during a call, arrival order, cancellation, `ask_client`.

Nothing sleeps. A backend blocks on events (`entered` says the worker is inside the call, `release`
lets it go), and the order of messages on the pipes is the synchronization: a `ping` is read by the
same thread that queues the calls, so its answer proves every earlier message was routed.
"""

import contextlib
import json
import os
import queue
import threading
from collections import defaultdict
from collections.abc import Callable, Iterator, Mapping

import pytest
from builders import RecordingBackend, make_gateway
from pydantic import JsonValue

from notary_core.models import CallProposed, DecisionMade
from notary_mcp_proxy import BackendResult
from notary_mcp_proxy.dispatch import (
    ClientClosedError,
    ClientRejectedError,
    ClientTimeoutError,
    Dispatcher,
    Wait,
)
from notary_mcp_proxy.jsonrpc import JsonObject, as_object, write_message
from notary_mcp_proxy.mcp_backend import RESULT_RECORD
from notary_mcp_proxy.server import LIST_CHANGED, ProxyServer

PATIENCE = 30.0
"""Only a failing test waits this long."""


class GatedBackend(RecordingBackend):
    """Blocks inside `call_tool` number n until `release[n]` is set."""

    def __init__(self) -> None:
        super().__init__()
        self.entered: defaultdict[int, threading.Event] = defaultdict(threading.Event)
        self.release: defaultdict[int, threading.Event] = defaultdict(threading.Event)
        self.gated: set[int] = set()
        self.resumed: Callable[[int], None] | None = None

    def call_tool(self, tool: str, args: Mapping[str, str]) -> BackendResult:
        number = len(self.calls) + 1
        answer = super().call_tool(tool, args)
        if number in self.gated:
            self.entered[number].set()
            assert self.release[number].wait(PATIENCE)
            if self.resumed is not None:
                self.resumed(number)
        return answer


class Wire:
    """A Dispatcher over two OS pipes, running on its own thread."""

    def __init__(
        self, backend: GatedBackend, *, wait: Wait | None = None, server: ProxyServer | None = None
    ) -> None:
        self.backend = backend
        self.server = server or ProxyServer(make_gateway(backend), [])
        in_r, in_w = os.pipe()
        out_r, out_w = os.pipe()
        self._to_proxy = os.fdopen(in_w, "wb")
        self._from_proxy = os.fdopen(out_r, "rb")
        self._proxy_in = os.fdopen(in_r, "rb")
        self._proxy_out = os.fdopen(out_w, "wb")
        if wait is None:
            self.dispatcher = Dispatcher(self.server, self._proxy_in, self._proxy_out)
        else:
            self.dispatcher = Dispatcher(self.server, self._proxy_in, self._proxy_out, wait=wait)
        self.lines: queue.Queue[str | None] = queue.Queue()
        self._pump = threading.Thread(target=self._read_output, daemon=True)
        self._pump.start()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self._ping = 1000

    def _run(self) -> None:
        self.dispatcher.run()
        self._proxy_out.close()  # the collector sees end of output

    def _read_output(self) -> None:
        for raw in iter(self._from_proxy.readline, b""):
            self.lines.put(raw.decode("utf-8"))
        self.lines.put(None)

    def send(self, message: JsonObject) -> None:
        write_message(self._to_proxy, message)

    def send_raw(self, line: bytes) -> None:
        self._to_proxy.write(line + b"\n")
        self._to_proxy.flush()

    def read_line(self) -> str:
        line = self.lines.get(timeout=PATIENCE)
        assert line is not None, "output ended"
        return line

    def read(self) -> JsonObject:
        message = as_object(json.loads(self.read_line()))
        assert message is not None
        return message

    def sync(self) -> None:
        """Round trip a ping: every message sent before it has been routed."""
        self._ping += 1
        self.send({"jsonrpc": "2.0", "id": self._ping, "method": "ping"})
        answer = self.read()
        assert answer["id"] == self._ping

    def close_input(self) -> None:
        self._to_proxy.close()

    def finish(self) -> list[JsonObject]:
        """Close the input, wait for the dispatcher and return what is left on the output."""
        self.close_input()
        self.thread.join(PATIENCE)
        assert not self.thread.is_alive()
        rest: list[JsonObject] = []
        while (line := self.lines.get(timeout=PATIENCE)) is not None:
            message = as_object(json.loads(line))
            assert message is not None
            rest.append(message)
        return rest

    def close(self) -> None:
        for stream in (self._to_proxy, self._from_proxy, self._proxy_in, self._proxy_out):
            stream.close()


@pytest.fixture
def backend() -> GatedBackend:
    return GatedBackend()


@pytest.fixture
def wires() -> Iterator[list[Wire]]:
    made: list[Wire] = []
    yield made
    for wire in made:
        for number in list(wire.backend.release):
            wire.backend.release[number].set()  # never leave a worker blocked
        wire.close_input()
        wire.thread.join(PATIENCE)
        wire.close()


@pytest.fixture
def make_wire(wires: list[Wire], backend: GatedBackend) -> Callable[..., Wire]:
    def make(wait: Wait | None = None, server: ProxyServer | None = None) -> Wire:
        wire = Wire(backend, wait=wait, server=server)
        wires.append(wire)
        return wire

    return make


def call(request_id: JsonValue, tool: str = "read_inbox") -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}},
    }


def cancel(request_id: JsonValue) -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": request_id},
    }


def proposed(wire: Wire) -> list[str]:
    return [
        e.event.proposal.call_id
        for e in wire.server.gateway.chain
        if isinstance(e.event, CallProposed)
    ]


def decided(wire: Wire) -> list[str]:
    return [e.event.call_id for e in wire.server.gateway.chain if isinstance(e.event, DecisionMade)]


def test_fast_methods_are_answered_while_a_call_runs(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    backend.gated = {1}
    wire = make_wire()
    wire.send(call(1))
    assert backend.entered[1].wait(PATIENCE)
    wire.send({"jsonrpc": "2.0", "id": 2, "method": "ping"})
    wire.send({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    wire.send({"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {}})
    wire.send({"jsonrpc": "2.0", "id": 5, "method": "no/such/method"})
    wire.send_raw(b"this is not json")
    answers = [wire.read() for _ in range(5)]
    by_id = {answer["id"]: answer for answer in answers}
    assert set(by_id) == {2, 3, 4, 5, None}  # the call is still running
    assert by_id[2]["result"] == {}
    assert "tools" in (as_object(by_id[3]["result"]) or {})
    assert as_object(by_id[4]["result"]) is not None
    assert (as_object(by_id[5]["error"]) or {})["code"] == -32601
    assert (as_object(by_id[None]["error"]) or {})["code"] == -32700
    backend.release[1].set()
    assert wire.read()["id"] == 1


def test_ping_is_answered_before_the_running_calls_answer(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    backend.gated = {1}
    wire = make_wire()
    wire.send(call(1))
    assert backend.entered[1].wait(PATIENCE)
    wire.send({"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert wire.read()["id"] == 2
    backend.release[1].set()
    answer = wire.read()
    assert answer["id"] == 1
    assert (as_object(answer["result"]) or {})["isError"] is False


def test_calls_are_decided_in_arrival_order(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    backend.gated = {1}
    wire = make_wire()
    wire.send(call(10))
    assert backend.entered[1].wait(PATIENCE)
    wire.send(call(11))
    wire.send(call(12))
    wire.sync()  # both are queued behind the running call
    assert proposed(wire) == ["c1"]
    backend.release[1].set()
    assert [wire.read()["id"] for _ in range(3)] == [10, 11, 12]
    assert proposed(wire) == ["c1", "c2", "c3"]
    assert decided(wire) == ["c1", "c2", "c3"]
    assert len(backend.calls) == 3


def test_cancel_of_a_queued_call_removes_it(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    backend.gated = {1}
    wire = make_wire()
    wire.send(call(1))
    assert backend.entered[1].wait(PATIENCE)
    wire.send(call(2))
    wire.send(call(3))
    wire.sync()
    wire.send(cancel(2))
    wire.sync()
    backend.release[1].set()
    assert wire.read()["id"] == 1
    assert wire.read()["id"] == 3  # the third call ran
    leftovers = wire.finish()
    assert leftovers == []  # no response for 2
    assert proposed(wire) == ["c1", "c2"]  # the cancelled call was never proposed
    assert len(backend.calls) == 2
    assert wire.dispatcher.cancelled(2) is False


def test_cancel_of_the_running_call_sets_the_flag_and_drops_the_response(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    backend.gated = {1}
    seen: list[bool] = []
    wire = make_wire()
    backend.resumed = lambda _number: seen.append(wire.dispatcher.cancelled(1))
    wire.send(call(1))
    assert backend.entered[1].wait(PATIENCE)
    assert wire.dispatcher.cancelled(1) is False
    wire.send(cancel(1))
    wire.sync()
    assert wire.dispatcher.cancelled(1) is True
    assert wire.dispatcher.cancelled(2) is False  # another id is not affected
    backend.release[1].set()
    leftovers = wire.finish()  # the worker is idle once the dispatcher returns
    assert seen == [True]  # visible to the worker
    assert leftovers == []  # no response
    assert decided(wire) == ["c1"]  # the logged decision stays in the chain
    assert proposed(wire) == ["c1"]
    assert wire.dispatcher.cancelled(1) is False


def test_cancel_of_an_unknown_or_finished_call_is_ignored(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    wire = make_wire()
    wire.send(call(1))
    assert wire.read()["id"] == 1
    for stray in (1, 99, "x", True, None):
        wire.send(cancel(stray))
    wire.send({"jsonrpc": "2.0", "method": "notifications/cancelled"})
    wire.send(call(2))
    assert wire.read()["id"] == 2
    assert proposed(wire) == ["c1", "c2"]


def test_end_of_input_finishes_the_running_call_and_drops_the_queue(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    backend.gated = {1}
    wire = make_wire()
    wire.send(call(1))
    assert backend.entered[1].wait(PATIENCE)
    wire.send(call(2))
    wire.sync()
    wire.close_input()
    assert wire.dispatcher.input_ended.wait(PATIENCE)
    assert wire.thread.is_alive()  # waits for the call in progress
    backend.release[1].set()
    rest = wire.finish()
    assert [m["id"] for m in rest] == [1]  # the running call was answered, the queued one dropped
    assert proposed(wire) == ["c1"]
    assert decided(wire) == ["c1"]
    assert len(backend.calls) == 1


def test_a_response_to_our_request_wakes_the_caller(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    wire = make_wire()
    outcome: queue.Queue[JsonObject | Exception] = queue.Queue()

    def ask(params: JsonObject) -> None:
        try:
            outcome.put(wire.dispatcher.ask_client("elicitation/create", params, timeout=PATIENCE))
        except Exception as failure:
            outcome.put(failure)

    first = threading.Thread(target=ask, args=({"message": "ok?"},), daemon=True)
    first.start()
    request = wire.read()
    assert request["id"] == "n1"
    assert request["method"] == "elicitation/create"
    assert request["params"] == {"message": "ok?"}
    wire.send({"jsonrpc": "2.0", "id": "n99", "result": {"action": "decline"}})  # not ours
    wire.send({"jsonrpc": "2.0", "id": 1, "result": {}})  # not ours either
    wire.sync()
    assert outcome.empty()
    wire.send({"jsonrpc": "2.0", "id": "n1", "result": {"action": "accept"}})
    assert outcome.get(timeout=PATIENCE) == {"action": "accept"}
    first.join(PATIENCE)
    second = threading.Thread(target=ask, args=({},), daemon=True)
    second.start()
    assert wire.read()["id"] == "n2"
    wire.send(
        {"jsonrpc": "2.0", "id": "n2", "error": {"code": -1, "message": "text the client wrote"}}
    )
    failure = outcome.get(timeout=PATIENCE)
    assert isinstance(failure, ClientRejectedError)
    assert "text the client wrote" not in str(failure)


def test_ask_client_times_out_and_tells_the_client_to_cancel(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    waited: list[float] = []

    def expire(event: threading.Event, timeout: float) -> bool:
        waited.append(timeout)
        return False  # the deadline passed without an answer

    wire = make_wire(wait=expire)
    with pytest.raises(ClientTimeoutError):
        wire.dispatcher.ask_client("elicitation/create", {}, timeout=7.5)
    assert waited == [7.5]
    assert wire.read()["id"] == "n1"
    cancelled = wire.read()
    assert cancelled["method"] == "notifications/cancelled"
    assert cancelled["params"] == {"requestId": "n1", "reason": "timeout"}
    wire.send({"jsonrpc": "2.0", "id": "n1", "result": {}})  # a late answer
    wire.sync()  # is ignored


def test_end_of_input_unblocks_ask_client_with_an_error(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    wire = make_wire()
    outcome: queue.Queue[Exception | None] = queue.Queue()

    def ask() -> None:
        try:
            wire.dispatcher.ask_client("elicitation/create", {}, timeout=PATIENCE)
            outcome.put(None)
        except Exception as failure:
            outcome.put(failure)

    thread = threading.Thread(target=ask, daemon=True)
    thread.start()
    assert wire.read()["id"] == "n1"
    wire.close_input()
    assert isinstance(outcome.get(timeout=PATIENCE), ClientClosedError)
    wire.thread.join(PATIENCE)
    with pytest.raises(ClientClosedError):  # and so does a later request
        wire.dispatcher.ask_client("elicitation/create", {}, timeout=1.0)


def test_concurrent_writes_never_interleave(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    big = "x" * 300_000  # far above the pipe's atomic write size
    inbox = backend.results["read_inbox"].model_copy(
        update={
            "records": tuple(
                record.model_copy(
                    update={
                        "record_id": RESULT_RECORD,
                        "fields": tuple(
                            field.model_copy(update={"text": big}) for field in record.fields
                        ),
                    }
                )
                for record in backend.results["read_inbox"].records
            )
        }
    )
    backend.results["read_inbox"] = inbox

    def expire(event: threading.Event, timeout: float) -> bool:
        return False

    wire = make_wire(wait=expire)
    askers = [
        threading.Thread(
            target=lambda: _ask_and_ignore(wire, {"filler": big[:100_000]}), daemon=True
        )
        for _ in range(4)
    ]
    for asker in askers:
        asker.start()
    wire.send(call(1))
    for index in range(100):
        wire.send({"jsonrpc": "2.0", "id": 100 + index, "method": "ping"})
    for asker in askers:
        asker.join(PATIENCE)
    wire.send({"jsonrpc": "2.0", "id": 9999, "method": "ping"})
    messages: list[JsonObject] = []
    seen: set[JsonValue] = set()
    while not {1, 9999} <= seen:  # the call's answer may come after the last ping's
        line = wire.read_line()
        assert line.endswith("\n")
        parsed = as_object(json.loads(line))  # one complete JSON object per line
        assert parsed is not None
        messages.append(parsed)
        seen.add(parsed.get("id"))
        if parsed.get("id") == 1:
            assert len(line) > 300_000  # the big answer arrived whole
    ping_ids = sorted(
        found for m in messages if isinstance(found := m.get("id"), int) and found >= 100
    )
    assert ping_ids == [*range(100, 200), 9999]
    assert sum(1 for m in messages if m.get("id") == 1) == 1


def _ask_and_ignore(wire: Wire, params: JsonObject) -> None:
    with contextlib.suppress(ClientTimeoutError):
        wire.dispatcher.ask_client("elicitation/create", params, timeout=1.0)


class WatchedServer(ProxyServer):
    """Records the thread each drift check runs on."""

    def __init__(self, backend: GatedBackend) -> None:
        super().__init__(make_gateway(backend), [])
        self.checks: list[tuple[str, int]] = []
        self.checked = threading.Event()
        self._backend = backend

    def check_drift_now(self) -> None:
        self.checks.append((threading.current_thread().name, len(self._backend.calls)))
        self.checked.set()


def test_drift_checks_run_on_the_worker_after_the_running_call(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    backend.gated = {1}
    server = WatchedServer(backend)
    wire = make_wire(server=server)
    wire.send(call(1))
    assert backend.entered[1].wait(PATIENCE)
    for _ in range(3):  # a burst, from another thread (the client's reader thread in real life)
        notify = threading.Thread(
            target=server.on_server_notification, args=(LIST_CHANGED, {}), daemon=True
        )
        notify.start()
        notify.join(PATIENCE)
    wire.sync()
    assert server.checks == []  # the worker is busy: the Gateway has one owner
    backend.release[1].set()
    assert wire.read()["id"] == 1
    assert server.checked.wait(PATIENCE)
    wire.send(call(2))
    assert wire.read()["id"] == 2
    assert server.checks == [("notary-worker", 1)]  # one check, coalesced, before call 2


def test_other_server_notifications_do_not_schedule_a_drift_check(
    backend: GatedBackend, make_wire: Callable[..., Wire]
) -> None:
    server = WatchedServer(backend)
    wire = make_wire(server=server)
    server.on_server_notification("notifications/message", {})
    wire.send(call(1))
    assert wire.read()["id"] == 1
    assert server.checks == []
