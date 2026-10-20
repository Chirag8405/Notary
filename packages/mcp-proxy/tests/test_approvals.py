"""Out-of-band approvals: an escalated call waits while the user answers on the control socket.

Nothing sleeps on the wall clock. The desk takes a fake clock; a test learns that a call is waiting
from `desk.wait_for_open`, and that a call is over from joining its thread or from the answer of a
call queued behind it. The only real time is `PATIENCE`, which a failing test waits out.
"""

import json
import os
import queue
import socket
import stat
import sys
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import IO

import pytest
from proxy_builders import RecordingBackend, make_gateway
from pydantic import JsonValue
from stdio_session import StdioSession, proxy_command, request, tool_call

from notary_core.audit import append
from notary_core.models import (
    AuditEntry,
    DecisionMade,
    EffectExecuted,
    EndorsementRequested,
    EndorsementResolved,
    Event,
    RunFinished,
)
from notary_mcp_proxy import BackendResult, RawCall
from notary_mcp_proxy.approvals import ApprovalDesk, Pending, printable
from notary_mcp_proxy.control import (
    MAX_LINE,
    ControlError,
    ControlServer,
    find_socket,
    prepare_directory,
    send,
)
from notary_mcp_proxy.dispatch import Dispatcher
from notary_mcp_proxy.gateway import Gateway
from notary_mcp_proxy.jsonrpc import JsonObject, as_object, write_message
from notary_mcp_proxy.main import main
from notary_mcp_proxy.server import ProxyServer

PATIENCE = 30.0
"""Only a failing test waits this long."""
NAME = "Alpha Consulting"
TIMEOUT = 120.0


class FakeClock:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._now = 1000.0

    def __call__(self) -> float:
        with self._lock:
            return self._now

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._now += seconds


class ThreadBackend(RecordingBackend):
    """Remembers which thread ran each tool."""

    def __init__(self) -> None:
        super().__init__()
        self.threads: list[int] = []

    def call_tool(self, tool: str, args: Mapping[str, str]) -> BackendResult:
        self.threads.append(threading.get_ident())
        return super().call_tool(tool, args)


def add_contact(request_id: JsonValue, name: str = NAME) -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "add_contact", "arguments": {"name": name}},
    }


def read_inbox(request_id: JsonValue) -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "read_inbox", "arguments": {}},
    }


def cancel(request_id: JsonValue) -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": request_id},
    }


def text_of(answer: JsonObject | None) -> str:
    assert answer is not None
    result = as_object(answer["result"])
    assert result is not None
    content = result["content"]
    assert isinstance(content, list)
    return "\n".join(str(block["text"]) for block in content if isinstance(block, dict))


def is_error(answer: JsonObject | None) -> bool:
    assert answer is not None
    result = as_object(answer["result"])
    assert result is not None
    return result["isError"] is True


class Rig:
    """A ProxyServer with a desk and a control socket, over an in-memory backend."""

    def __init__(self, directory: Path, *, max_approvals: int = 3) -> None:
        self.backend = ThreadBackend()
        self.gateway: Gateway = make_gateway(self.backend, max_approvals=max_approvals)
        self.clock = FakeClock()
        self.desk = ApprovalDesk(timeout_seconds=TIMEOUT, clock=self.clock, poll_seconds=0.005)
        self.server = ProxyServer(self.gateway, [], self.desk, control_hint="hint {id}")
        self.path = directory / "c" / "p.sock"
        self.control = ControlServer(self.desk, self.path)
        self.control.start()
        self.opened = 0

    def start_call(self, message: JsonObject) -> "RunningCall":
        return RunningCall(self.server, message)

    def waiting(self, call: "RunningCall") -> None:
        """Block until the call has opened its card on the desk."""
        self.opened += 1
        assert self.desk.wait_for_open(self.opened, PATIENCE)
        assert call.thread.is_alive()

    def ask(self, op: str, endorsement_id: str | None = None) -> JsonObject:
        message: JsonObject = {"op": op}
        if endorsement_id is not None:
            message["endorsement_id"] = endorsement_id
        return send(self.path, message)

    def types(self) -> list[str]:
        return [entry.event.type for entry in self.gateway.chain]

    def outcomes(self) -> list[str]:
        """The `endorsement_resolved` outcomes in the chain, in order."""
        return [
            entry.event.outcome
            for entry in self.gateway.chain
            if isinstance(entry.event, EndorsementResolved)
        ]

    def summary(self) -> str:
        """The `run_finished` summary after the agent closed the connection."""
        self.server.finish_run()
        last = self.gateway.chain[-1].event
        assert isinstance(last, RunFinished)
        return last.summary

    def verdicts(self) -> list[str]:
        return [
            e.event.decision.verdict
            for e in self.gateway.chain
            if isinstance(e.event, DecisionMade)
        ]


class RunningCall:
    """`ProxyServer.handle` on its own thread, as the dispatcher's worker runs it."""

    def __init__(self, server: ProxyServer, message: JsonObject) -> None:
        self.answer: JsonObject | None = None
        self.ident = 0
        self._server = server
        self._message = message
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        self.ident = threading.get_ident()
        self.answer = self._server.handle(self._message)

    def result(self) -> JsonObject:
        self.thread.join(PATIENCE)
        assert not self.thread.is_alive(), "the call is still waiting"
        assert self.answer is not None
        return self.answer


@pytest.fixture
def make_rig(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Callable[..., Rig]]:
    rigs: list[Rig] = []

    def make(*, max_approvals: int = 3) -> Rig:
        rig = Rig(tmp_path_factory.mktemp("ap"), max_approvals=max_approvals)
        rigs.append(rig)
        return rig

    yield make
    for rig in rigs:
        rig.control.close()


# -- the behavior of the issue ---------------------------------------------------------------------


@pytest.mark.invariant("I4")
def test_approve_runs_the_call(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()
    call = rig.start_call(add_contact(1))
    rig.waiting(call)
    cards = rig.ask("pending")["pending"]
    assert isinstance(cards, list)
    card = as_object(cards[0])
    assert card is not None
    assert (card["endorsement_id"], card["call_id"], card["tool"]) == ("e1", "c1", "add_contact")
    assert card["remaining_approvals"] == 3
    assert NAME.lower() in str(card["card_text"])
    assert rig.backend.calls == []  # waiting, nothing ran
    assert rig.ask("approve", "e1") == {"ok": True}
    answer = call.result()
    assert not is_error(answer)
    assert rig.backend.calls == [("add_contact", {"name": NAME})]
    assert rig.outcomes() == ["approved"]
    assert rig.types() == [
        "value_labeled",
        "call_proposed",
        "decision_made",
        "endorsement_requested",
        "endorsement_resolved",
        "decision_made",
        "effect_executed",
    ]
    assert rig.verdicts() == ["ESCALATE", "ALLOW"]
    assert any(isinstance(e.event, EffectExecuted) for e in rig.gateway.chain)
    assert rig.gateway.session.approvals_used == 1
    assert [e.ledger for e in rig.gateway.ledger][-1] == "endorsed"
    assert rig.summary().endswith("; approved: e1")


@pytest.mark.invariant("I4")
def test_the_approval_is_applied_on_the_worker_thread(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()
    call = rig.start_call(add_contact(1))
    rig.waiting(call)
    assert rig.ask("approve", "e1") == {"ok": True}
    call.result()
    assert rig.backend.threads == [call.ident]
    assert call.ident != threading.get_ident()


@pytest.mark.invariant("I4")
def test_reject_has_no_effect(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()
    call = rig.start_call(add_contact(1))
    rig.waiting(call)
    ledger, session = rig.gateway.ledger, rig.gateway.session
    assert rig.ask("reject", "e1") == {"ok": True}
    answer = call.result()
    assert is_error(answer)
    assert text_of(answer) == "NOTARY blocked add_contact: the user rejected the endorsement"
    assert rig.backend.calls == []
    assert (rig.gateway.ledger, rig.gateway.session) == (ledger, session)
    assert rig.gateway.session.approvals_used == 0
    assert rig.verdicts() == ["ESCALATE"]
    assert "effect_executed" not in rig.types()
    assert rig.gateway.pending_endorsements() == ()
    assert rig.gateway.approve("e1", ()) is None  # no card is left that could be approved later
    assert rig.outcomes() == ["rejected"]
    assert rig.summary().endswith("; rejected: e1 (user)")


def test_timeout_rejects(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()
    call = rig.start_call(add_contact(1))
    rig.waiting(call)
    rig.clock.advance(TIMEOUT - 1)
    rig.desk.wake()
    assert call.thread.is_alive()  # not yet: one second left
    rig.clock.advance(1)
    answer = call.result()
    assert is_error(answer)
    assert text_of(answer) == "NOTARY blocked add_contact: no answer within 120 s"
    assert rig.backend.calls == []
    assert rig.gateway.session.approvals_used == 0
    assert rig.ask("approve", "e1") == {
        "ok": False,
        "error": "unknown or already decided endorsement",
    }
    assert rig.gateway.pending_endorsements() == ()
    assert rig.gateway.approve("e1", ()) is None
    assert "effect_executed" not in rig.types()
    assert rig.outcomes() == ["timed_out"]
    assert rig.summary().endswith("; rejected: e1 (timeout)")


def test_a_late_approval_never_counts() -> None:
    clock = FakeClock()
    desk = ApprovalDesk(timeout_seconds=10, clock=clock)
    desk.open(
        Pending(endorsement_id="e1", call_id="c1", tool="t", card_text="", remaining_approvals=1)
    )
    clock.advance(10)  # the deadline passed; the waiting call has not looked yet
    assert desk.pending() == ()
    assert not desk.decide("e1", "approve")
    assert desk.wait("e1", lambda: False) == "reject"


# -- cancel and end of input go through the real dispatcher ----------------------------------------


class Wire:
    def __init__(self, server: ProxyServer) -> None:
        in_r, in_w = os.pipe()
        out_r, out_w = os.pipe()
        self._to_proxy: IO[bytes] = os.fdopen(in_w, "wb")
        self._from_proxy: IO[bytes] = os.fdopen(out_r, "rb")
        self._proxy_in: IO[bytes] = os.fdopen(in_r, "rb")
        self._proxy_out: IO[bytes] = os.fdopen(out_w, "wb")
        self.dispatcher = Dispatcher(server, self._proxy_in, self._proxy_out)
        self.lines: queue.Queue[str | None] = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        self.dispatcher.run()
        self._proxy_out.close()

    def _pump(self) -> None:
        for raw in iter(self._from_proxy.readline, b""):
            self.lines.put(raw.decode("utf-8"))
        self.lines.put(None)

    def send(self, message: JsonObject) -> None:
        write_message(self._to_proxy, message)

    def read(self) -> JsonObject:
        line = self.lines.get(timeout=PATIENCE)
        assert line is not None, "output ended"
        message = as_object(json.loads(line))
        assert message is not None
        return message

    def close_input(self) -> None:
        self._to_proxy.close()

    def finish(self) -> list[JsonObject]:
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
def wire(make_rig: Callable[..., Rig]) -> Iterator[tuple[Rig, Wire]]:
    rig = make_rig()
    made = Wire(rig.server)
    yield rig, made
    made.close_input()
    made.thread.join(PATIENCE)
    made.close()


@pytest.mark.invariant("I4")
def test_client_cancel_rejects_without_a_response(wire: tuple[Rig, Wire]) -> None:
    rig, w = wire
    w.send(add_contact(7))
    assert rig.desk.wait_for_open(1, PATIENCE)
    w.send({"jsonrpc": "2.0", "id": 8, "method": "ping"})
    assert w.read()["id"] == 8  # fast methods answer while the call waits
    w.send(read_inbox(9))  # queued behind the waiting call
    w.send(cancel(7))
    answer = w.read()  # the first answer is call 9's: the call 7 got none
    assert answer["id"] == 9
    assert not is_error(answer)
    assert rig.backend.calls == [("read_inbox", {})]  # the contact was never added
    assert rig.gateway.session.approvals_used == 0
    assert rig.desk.pending() == ()
    assert rig.gateway.pending_endorsements() == ()
    assert rig.ask("approve", "e1")["ok"] is False
    assert rig.outcomes() == ["cancelled"]
    assert w.finish() == []


@pytest.mark.invariant("I4")
def test_end_of_input_while_waiting_rejects(wire: tuple[Rig, Wire]) -> None:
    rig, w = wire
    w.send(add_contact(7))
    assert rig.desk.wait_for_open(1, PATIENCE)
    rest = w.finish()  # the loop ended: the worker saw the end of input and rejected
    assert all(is_error(message) for message in rest)  # a late answer, if any, is a refusal
    assert rig.backend.calls == []
    assert rig.verdicts() == ["ESCALATE"]
    assert rig.outcomes() == ["cancelled"]
    assert rig.gateway.pending_endorsements() == ()
    assert rig.desk.pending() == ()


def test_calls_behind_a_waiting_call_keep_their_order(wire: tuple[Rig, Wire]) -> None:
    rig, w = wire
    w.send(add_contact(1))
    assert rig.desk.wait_for_open(1, PATIENCE)
    w.send(read_inbox(2))
    w.send({"jsonrpc": "2.0", "id": 3, "method": "ping"})
    assert w.read()["id"] == 3
    assert rig.backend.calls == []  # the read waits behind the card
    assert rig.ask("reject", "e1") == {"ok": True}
    first, second = w.read(), w.read()
    assert (first["id"], second["id"]) == (1, 2)
    assert is_error(first)
    assert not is_error(second)


# -- the budget ------------------------------------------------------------------------------------


@pytest.mark.attack("A11")
def test_no_approvals_left_blocks_without_waiting(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig(max_approvals=0)
    answer = rig.server.handle(add_contact(1))
    assert is_error(answer)
    assert "BUDGET_APPROVALS_EXHAUSTED" in text_of(answer)
    assert not rig.desk.wait_for_open(1, 0)  # no card was ever opened
    assert rig.backend.calls == []


@pytest.mark.attack("A11")
def test_second_escalation_is_refused_by_the_monitor(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig(max_approvals=1)
    first = rig.start_call(add_contact(1))
    rig.waiting(first)
    assert rig.ask("approve", "e1") == {"ok": True}
    assert not is_error(first.result())
    second = rig.server.handle(add_contact(2, "Bravo Holdings"))  # does not wait
    assert is_error(second)
    assert "BUDGET_APPROVALS_EXHAUSTED" in text_of(second)
    assert rig.backend.calls == [("add_contact", {"name": NAME})]
    assert rig.desk.pending() == ()


# -- idempotence and refusal -----------------------------------------------------------------------


@pytest.mark.invariant("I4")
def test_a_second_approval_never_runs_the_tool_twice(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()
    call = rig.start_call(add_contact(1))
    rig.waiting(call)
    assert rig.ask("approve", "e1") == {"ok": True}
    again = rig.ask("approve", "e1")  # before or after the worker looked: refused either way
    assert again["ok"] is False
    call.result()
    assert rig.ask("approve", "e1")["ok"] is False
    assert rig.ask("reject", "e1")["ok"] is False
    assert len(rig.backend.calls) == 1
    assert rig.gateway.session.approvals_used == 1


@pytest.mark.invariant("I4")
def test_unknown_and_malformed_requests_change_nothing(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()
    call = rig.start_call(add_contact(1))
    rig.waiting(call)
    assert rig.ask("approve", "e9") == {
        "ok": False,
        "error": "unknown or already decided endorsement",
    }
    assert rig.ask("approve", "E1")["ok"] is False
    assert rig.ask("delete")["ok"] is False
    assert rig.ask("approve")["ok"] is False
    assert rig.control.handle(b"not json") == {"ok": False, "error": "bad request"}
    assert rig.control.handle(b"[1]") == {"ok": False, "error": "bad request"}
    assert rig.control.handle(b'{"op": "approve", "endorsement_id": 1}')["ok"] is False
    assert len(rig.desk.pending()) == 1  # still waiting
    assert rig.ask("reject", "e1") == {"ok": True}
    call.result()


def test_an_oversize_request_is_refused(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()
    big: JsonObject = {"op": "pending", "pad": "x" * (MAX_LINE + 10)}
    assert send(rig.path, big) == {"ok": False, "error": "bad request"}


def test_the_card_cannot_drive_a_terminal(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()
    call = rig.start_call(add_contact(1, "Eve\x1b[2J\x07"))
    rig.waiting(call)
    cards = rig.ask("pending")["pending"]
    assert isinstance(cards, list)
    card = as_object(cards[0])
    assert card is not None
    assert "\x1b" not in str(card["card_text"])
    assert "\\u001b" in str(card["card_text"])
    assert printable("a\nb\x00") == "a\nb\\u0000"
    rig.ask("reject", "e1")
    call.result()


# -- the channel -----------------------------------------------------------------------------------


def test_socket_and_directory_permissions(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig()
    assert stat.S_IMODE(os.stat(rig.path).st_mode) == 0o600
    assert stat.S_ISSOCK(os.stat(rig.path).st_mode)
    assert stat.S_IMODE(os.stat(rig.path.parent).st_mode) == 0o700
    rig.control.close()
    assert not rig.path.exists()


def test_a_shared_directory_is_tightened(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    prepare_directory(shared)
    assert stat.S_IMODE(os.stat(shared).st_mode) == 0o700


def test_a_link_in_place_of_the_directory_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ControlError, match="plain directory"):
        prepare_directory(link)


def test_a_stale_socket_is_replaced_and_a_live_one_is_not(
    make_rig: Callable[..., Rig], tmp_path_factory: pytest.TempPathFactory
) -> None:
    rig = make_rig()
    with pytest.raises(ControlError, match="in use"):
        ControlServer(rig.desk, rig.path).start()
    assert rig.ask("pending") == {"pending": []}  # the live one still answers
    directory = tmp_path_factory.mktemp("st")
    stale = directory / "s.sock"
    crashed = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    crashed.bind(str(stale))
    crashed.close()  # a proxy that died leaves its socket file behind
    assert stale.exists()
    again = ControlServer(rig.desk, stale)
    again.start()
    assert send(stale, {"op": "pending"}) == {"pending": []}
    again.close()


def test_find_socket_needs_exactly_one(tmp_path: Path) -> None:
    with pytest.raises(ControlError, match="found 0"):
        find_socket(tmp_path)
    (tmp_path / "a.sock").write_text("")
    assert find_socket(tmp_path) == tmp_path / "a.sock"
    (tmp_path / "b.sock").write_text("")
    with pytest.raises(ControlError, match="found 2"):
        find_socket(tmp_path)


def test_without_a_desk_every_escalation_is_rejected_at_once() -> None:
    backend = RecordingBackend()
    gateway = make_gateway(backend)
    server = ProxyServer(gateway, [], reject_unanswered=True)  # `--control none`
    answer = server.handle(add_contact(1))
    assert is_error(answer)
    assert "NOTARY escalated add_contact (e1)" in text_of(answer)
    assert "approvals are disabled" in text_of(answer)
    assert "LEDGER_NOVEL_ESCALATE" in text_of(answer) or "ENDORSE" in text_of(answer)
    assert backend.calls == []
    assert gateway.pending_endorsements() == ()
    requested = [e for e in gateway.chain if isinstance(e.event, EndorsementRequested)]
    assert len(requested) == 1  # the card was logged, then closed
    assert [e.event.outcome for e in gateway.chain if isinstance(e.event, EndorsementResolved)] == [
        "rejected"
    ]
    assert gateway.reject("e1") is None


def test_an_embedder_without_a_desk_keeps_the_endorsement_pending() -> None:
    backend = RecordingBackend()
    gateway = make_gateway(backend)
    answer = ProxyServer(gateway, []).handle(add_contact(1))
    assert "NOTARY escalated add_contact (e1)" in text_of(answer)
    assert len(gateway.pending_endorsements()) == 1  # the embedder resolves it on the Gateway
    assert backend.calls == []


def test_pending_endorsements_is_a_read_only_snapshot() -> None:
    gateway = make_gateway(RecordingBackend(), max_approvals=2)
    assert gateway.pending_endorsements() == ()
    server = ProxyServer(gateway, [], ApprovalDesk(timeout_seconds=1))
    gateway.propose(server_call("c1"))
    (card,) = gateway.pending_endorsements()
    assert card.endorsement.endorsement_id == "e1"
    assert card.decision.verdict == "ESCALATE"
    assert card.remaining_approvals == 2
    assert card.proposal.call_id == "c1"
    gateway.reject("e1")
    assert gateway.pending_endorsements() == ()
    assert server.gateway is gateway


def server_call(call_id: str) -> RawCall:
    return RawCall(call_id=call_id, tool="add_contact", args={"name": NAME})


# -- the CLI ---------------------------------------------------------------------------------------


def test_cli_pending_approve_and_refusals(
    make_rig: Callable[..., Rig], capsys: pytest.CaptureFixture[str]
) -> None:
    rig = make_rig()
    path = str(rig.path)
    assert main(["pending", "--control", path]) == 0
    assert "no escalation is waiting" in capsys.readouterr().out
    call = rig.start_call(add_contact(1))
    rig.waiting(call)
    assert main(["pending", "--control", path]) == 0
    shown = capsys.readouterr().out
    assert "e1: add_contact (call c1)" in shown
    assert NAME.lower() in shown
    assert main(["approve", "e9", "--control", path]) == 1
    assert "unknown or already decided" in capsys.readouterr().err
    assert main(["approve", "e1", "--control", path]) == 0
    assert capsys.readouterr().out == "approved e1\n"
    assert not is_error(call.result())
    assert main(["reject", "e1", "--control", path]) == 1
    rig.control.close()
    assert main(["pending", "--control", path]) == 2
    assert "cannot reach the proxy" in capsys.readouterr().err


# -- the real proxy over stdio, the toy bank ------------------------------------------------


class WatchedSession(StdioSession):
    """A stdio session whose stderr lines can be waited for (no polling)."""

    def __init__(self, command: list[str]) -> None:
        self.watched: queue.Queue[str] = queue.Queue()
        super().__init__(command)

    def _pump_err(self, stream: IO[bytes]) -> None:
        for raw in iter(stream.readline, b""):
            line = raw.decode("utf-8")
            self._err.append(line)
            self.watched.put(line)

    def wait_for_line(self, needle: str) -> str:
        while True:
            line = self.watched.get(timeout=PATIENCE)
            if needle in line:
                return line


BANK = Path(__file__).resolve().parents[1] / "examples" / "bank"


def test_bank_demo_one_approve_one_reject_and_the_payment_check(
    tmp_path_factory: pytest.TempPathFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = tmp_path_factory.mktemp("bk")
    data = json.loads((BANK / "notary.json").read_text())
    data["server"]["command"] = [sys.executable, str(BANK / "server.py")]
    config = directory / "notary.json"
    config.write_text(json.dumps(data))
    socket_path = directory / "ctl" / "bank.sock"
    session = WatchedSession(
        proxy_command(config, "--control", str(socket_path), "--approval-timeout", "60")
    )
    session.send(request(1, "initialize", {"protocolVersion": "2025-06-18"}))
    session.result(1)
    # approve
    session.send(tool_call(2, "add_contact", {"name": "Alpha Consulting"}))
    hint = session.wait_for_line("approve with")
    assert str(socket_path) in hint
    assert main(["approve", "e1", "--control", str(socket_path)]) == 0
    approved = session.result(2)
    assert approved["isError"] is False
    assert "added contact Alpha Consulting" in json.dumps(approved)
    # reject
    session.send(tool_call(3, "add_contact", {"name": "Mallory"}))
    session.wait_for_line("approve with")
    assert main(["reject", "e2", "--control", str(socket_path)]) == 0
    rejected = session.result(3)
    assert rejected["isError"] is True
    assert "the user rejected the endorsement" in json.dumps(rejected)
    # the payment check of the demo is unchanged: attacker IBAN blocked, ledger payee paid
    session.send(tool_call(4, "pay_bill", {"payee": "DE00ATTACKER0000000001", "amount": 120}))
    assert "LEDGER_NOT_FOUND" in json.dumps(session.result(4))
    session.send(tool_call(5, "pay_bill", {"payee": "DE00ACME00000000000001", "amount": 120}))
    assert session.result(5)["isError"] is False
    err = session.finish()
    assert "e1: approved by the user" in err
    assert "e2: rejected (user)" in err
    assert not socket_path.exists()  # removed at shutdown
    capsys.readouterr()


def test_control_none_over_stdio_rejects_at_once(tmp_path_factory: pytest.TempPathFactory) -> None:
    directory = tmp_path_factory.mktemp("nn")
    data = json.loads((BANK / "notary.json").read_text())
    data["server"]["command"] = [sys.executable, str(BANK / "server.py")]
    config = directory / "notary.json"
    config.write_text(json.dumps(data))
    session = WatchedSession(proxy_command(config, "--control", "none"))
    session.send(request(1, "initialize", {"protocolVersion": "2025-06-18"}))
    session.result(1)
    session.send(tool_call(2, "add_contact", {"name": "Alpha Consulting"}))
    answer = session.result(2)
    assert answer["isError"] is True
    assert "NOTARY escalated add_contact (e1)" in json.dumps(answer)
    assert "approvals are disabled" in json.dumps(answer)
    err = session.finish()
    assert "approvals disabled" in err


@pytest.mark.invariant("I4")
@pytest.mark.parametrize("answer", ["approve", "reject"])
def test_a_resolution_that_cannot_be_logged_is_not_applied(answer: str) -> None:
    """The outcome is appended before the ledger changes; if that fails nothing is applied."""
    refuse = {"on": False}

    def audit_append(chain: Sequence[AuditEntry], event: Event) -> tuple[AuditEntry, ...]:
        if refuse["on"] and isinstance(event, EndorsementResolved):
            raise RuntimeError("disk full")
        return append(chain, event)

    backend = RecordingBackend()
    gateway = make_gateway(backend, audit_append=audit_append)
    outcome = gateway.propose(RawCall(call_id="c1", tool="add_contact", args={"name": NAME}))
    assert outcome.status == "escalated"
    ledger, session = gateway.ledger, gateway.session
    refuse["on"] = True
    result = gateway.approve("e1", ()) if answer == "approve" else gateway.reject("e1")
    assert result is not None
    assert result.status == "halted"
    assert (gateway.ledger, gateway.session) == (ledger, session)
    assert backend.calls == []
    assert not any(isinstance(e.event, EndorsementResolved) for e in gateway.chain)
