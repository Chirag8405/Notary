"""Approve or reject an MCP proxy escalation from the X-ray's endorsement card (#262).

The unit tests use a socketpair as the "control socket" (the injected `connect`), so no test waits
on a clock. The end-to-end test runs the real proxy as a child process in front of the toy bank
and drives the app in process: the card resolves only because the proxy's chain shows the effect.
"""

import json
import queue
import socket
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import IO

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.testclient import WebSocketTestSession
from starlette.websockets import WebSocketDisconnect
from test_mcp_runs import entries_of, run_events, until_closed

from notary_core.models import (
    DecisionMade,
    EndorsementDecisionCommand,
    EndorsementRequested,
    Event,
)
from notary_mcp_proxy.audit_log import RunLog
from notary_mcp_proxy.jsonrpc import JsonObject, as_object
from notary_server.app import create_app, is_loopback_host
from notary_server.commands import CommandContext, CommandRejected
from notary_server.mcp_runs import (
    CONTROL_SUFFIX,
    REASON_NOT_ACCEPTED,
    REASON_NOT_DELIVERED,
    REASON_NOT_SUPPORTED,
    McpApprovals,
    McpRunsSource,
)
from notary_server.wiring import Settings, build_app
from notary_world.golden import EVENT_ADAPTER

RUN = "mcp-0123456789ab"
LOCAL = ("127.0.0.1", 50000)
BANK = Path(__file__).resolve().parents[3] / "packages" / "mcp-proxy" / "examples" / "bank"
PATIENCE = 30.0
"""Only a failing test waits this long."""


def frame(choice: str, endorsement_id: str = "e1", run_id: str = RUN) -> str:
    return json.dumps(
        {
            "type": "endorsement_decision",
            "run_id": run_id,
            "endorsement_id": endorsement_id,
            "decision": choice,
        }
    )


def command(choice: str, endorsement_id: str = "e1") -> EndorsementDecisionCommand:
    return EndorsementDecisionCommand.model_validate_json(frame(choice, endorsement_id))


CONTEXT = CommandContext(run_id=RUN, lane="notary", owner="owner")


class FakeControl:
    """The proxy's side of a control socket: records each line and answers it."""

    def __init__(self, reply: bytes = b'{"ok": true}\n') -> None:
        self.received: list[bytes] = []
        self.connects: list[Path] = []
        self.replied = threading.Event()
        self._reply = reply
        self._threads: list[threading.Thread] = []

    def connect(self, path: Path) -> socket.socket:
        self.connects.append(path)
        near, far = socket.socketpair()
        thread = threading.Thread(target=self._serve, args=(far,), daemon=True)
        thread.start()
        self._threads.append(thread)
        return near

    def _serve(self, connection: socket.socket) -> None:
        with connection, connection.makefile("rwb") as stream:
            self.received.append(stream.readline())
            stream.write(self._reply)
            stream.flush()
        self.replied.set()

    def join(self) -> None:
        for thread in self._threads:
            thread.join(timeout=PATIENCE)


def announce(directory: Path, socket_path: str, run_id: str = RUN) -> None:
    (directory / (run_id + CONTROL_SUFFIX)).write_text(json.dumps({"socket": socket_path}), "utf-8")


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    runs = tmp_path / "runs"
    control = tmp_path / "control"
    runs.mkdir()
    control.mkdir()
    return runs, control


def approvals(dirs: tuple[Path, Path], fake: FakeControl) -> McpApprovals:
    runs, control = dirs
    return McpApprovals(runs, control_directory=control, connect=fake.connect)


def handle(approver: McpApprovals, cmd: EndorsementDecisionCommand) -> CommandRejected | None:
    try:
        approver.handler()(cmd, CONTEXT)
    except CommandRejected as rejected:
        return rejected
    return None


# -- forwarding ------------------------------------------------------------------------------------


@pytest.mark.parametrize("choice", ["approve", "reject"])
def test_approve_and_reject_are_forwarded_to_the_control_socket(
    dirs: tuple[Path, Path], choice: str
) -> None:
    runs, control = dirs
    announce(runs, str(control / "a.sock"))
    fake = FakeControl()
    assert handle(approvals(dirs, fake), command(choice)) is None
    fake.join()
    assert fake.received == [json.dumps({"op": choice, "endorsement_id": "e1"}).encode() + b"\n"]
    assert fake.connects == [(control / "a.sock").resolve()]


NL = b"\n"


def test_the_approval_code_is_forwarded_with_an_approve_and_dropped_from_a_reject(
    dirs: tuple[Path, Path],
) -> None:
    runs, control = dirs
    announce(runs, str(control / "a.sock"))
    fake = FakeControl()
    approver = approvals(dirs, fake)
    with_code = command("approve").model_copy(update={"code": "K7Q2M9XA"})
    assert handle(approver, with_code) is None
    assert handle(approver, with_code.model_copy(update={"decision": "reject"})) is None
    fake.join()
    assert fake.received == [
        json.dumps({"op": "approve", "endorsement_id": "e1", "code": "K7Q2M9XA"}).encode() + NL,
        json.dumps({"op": "reject", "endorsement_id": "e1"}).encode() + NL,
    ]


def test_a_code_longer_than_the_limit_is_not_a_command() -> None:
    too_long = json.loads(frame("approve")) | {"code": "A" * 65}
    with pytest.raises(ValueError, match="code"):
        EndorsementDecisionCommand.model_validate_json(json.dumps(too_long))


def test_use_nearest_is_rejected_with_a_fixed_reason_and_nothing_is_forwarded(
    dirs: tuple[Path, Path],
) -> None:
    runs, control = dirs
    announce(runs, str(control / "a.sock"))
    fake = FakeControl()
    rejected = handle(approvals(dirs, fake), command("use_nearest"))
    assert rejected is not None
    assert (rejected.code, rejected.reason) == (4422, REASON_NOT_SUPPORTED)
    assert fake.connects == []


@pytest.mark.parametrize("choice", ["user_prompt", "pending", "approve ", "APPROVE", ""])
def test_the_card_can_never_make_the_forwarder_send_another_op(
    dirs: tuple[Path, Path], choice: str
) -> None:
    """The proxy's control socket also takes `user_prompt` (the user's own words, trusted). The
    forwarder serves the card only: a decision outside `approve` / `reject` is not a command at
    all (the model's `decision` is a closed set), so no frame can reach a control socket as a
    `user_prompt`, and the line sent for the two real decisions is exactly their op."""
    runs, control = dirs
    announce(runs, str(control / "a.sock"))
    fake = FakeControl()
    with pytest.raises(ValidationError):
        command(choice)
    assert handle(approvals(dirs, fake), command("approve")) is None
    assert handle(approvals(dirs, fake), command("reject")) is None
    fake.join()
    sent = [json.loads(line) for line in fake.received]
    assert [message["op"] for message in sent] == ["approve", "reject"]
    assert all(set(message) == {"op", "endorsement_id"} for message in sent)


@pytest.mark.parametrize("op", ["user_prompt", "pending", "approve ", "APPROVE", "", "use_nearest"])
def test_forward_itself_refuses_any_op_but_approve_and_reject(
    dirs: tuple[Path, Path], op: str
) -> None:
    """The guard is in `forward`, not only in the command model: a direct caller (a bug, a new
    command) cannot make the server send `user_prompt` or anything else to a control socket."""
    runs, control = dirs
    announce(runs, str(control / "a.sock"))
    fake = FakeControl()
    with pytest.raises(CommandRejected) as refused:
        approvals(dirs, fake).forward(RUN, "e1", op)
    assert refused.value.reason == REASON_NOT_SUPPORTED
    assert fake.connects == []


def test_a_refusal_by_the_proxy_is_a_rejection_with_a_fixed_reason(dirs: tuple[Path, Path]) -> None:
    runs, control = dirs
    announce(runs, str(control / "a.sock"))
    fake = FakeControl(b'{"ok": false, "error": "text of the proxy \\u001b[2J"}\n')
    rejected = handle(approvals(dirs, fake), command("approve"))
    fake.join()
    assert rejected is not None
    assert (rejected.code, rejected.reason) == (4409, REASON_NOT_ACCEPTED)


@pytest.mark.parametrize("reply", [b"", b"not json\n", b'{"ok": "yes"}\n', b"[]\n"])
def test_an_answer_that_is_not_ok_or_not_ok_false_is_not_delivered(
    dirs: tuple[Path, Path], reply: bytes
) -> None:
    runs, control = dirs
    announce(runs, str(control / "a.sock"))
    fake = FakeControl(reply)
    rejected = handle(approvals(dirs, fake), command("approve"))
    fake.join()
    assert rejected is not None
    assert (rejected.code, rejected.reason) == (4409, REASON_NOT_DELIVERED)


def test_an_unreachable_socket_is_a_rejection(dirs: tuple[Path, Path]) -> None:
    runs, control = dirs
    announce(runs, str(control / "gone.sock"))

    def refuse(path: Path) -> socket.socket:
        raise ConnectionRefusedError(str(path))

    approver = McpApprovals(runs, control_directory=control, connect=refuse)
    rejected = handle(approver, command("approve"))
    assert rejected is not None
    assert (rejected.code, rejected.reason) == (4409, REASON_NOT_DELIVERED)
    # and the real connect, to a path nobody listens on
    real = McpApprovals(runs, control_directory=control)
    again = handle(real, command("approve"))
    assert again is not None
    assert again.reason == REASON_NOT_DELIVERED


# -- the control file is not trusted ---------------------------------------------------------------


def not_delivered(dirs: tuple[Path, Path], fake: FakeControl) -> None:
    rejected = handle(approvals(dirs, fake), command("approve"))
    assert rejected is not None
    assert (rejected.code, rejected.reason) == (4409, REASON_NOT_DELIVERED)
    assert fake.connects == []


def test_a_relative_socket_path_is_refused(dirs: tuple[Path, Path]) -> None:
    runs, _ = dirs
    announce(runs, "control/a.sock")
    not_delivered(dirs, FakeControl())


def test_a_socket_outside_the_control_directory_is_refused(
    dirs: tuple[Path, Path], tmp_path: Path
) -> None:
    runs, control = dirs
    for outside in (tmp_path / "other.sock", Path("/etc/passwd"), control / ".." / "x.sock"):
        announce(runs, str(outside))
        not_delivered(dirs, FakeControl())


def test_a_link_inside_the_control_directory_to_the_outside_is_refused(
    dirs: tuple[Path, Path], tmp_path: Path
) -> None:
    runs, control = dirs
    (control / "trap.sock").symlink_to(tmp_path / "elsewhere.sock")
    announce(runs, str(control / "trap.sock"))
    not_delivered(dirs, FakeControl())


@pytest.mark.parametrize(
    "body",
    ["", "not json", "[]", "{}", '{"socket": 3}', '{"socket": ""}', '{"socket": "/a", "x": 1}'],
)
def test_a_control_file_that_is_not_the_announcement_is_refused(
    dirs: tuple[Path, Path], body: str
) -> None:
    runs, _ = dirs
    (runs / (RUN + CONTROL_SUFFIX)).write_text(body, "utf-8")
    not_delivered(dirs, FakeControl())


def test_a_missing_or_linked_or_oversized_control_file_is_refused(
    dirs: tuple[Path, Path], tmp_path: Path
) -> None:
    runs, control = dirs
    not_delivered(dirs, FakeControl())  # missing
    real = tmp_path / "real.json"
    real.write_text(json.dumps({"socket": str(control / "a.sock")}), "utf-8")
    (runs / (RUN + CONTROL_SUFFIX)).symlink_to(real)
    not_delivered(dirs, FakeControl())  # a link
    (runs / (RUN + CONTROL_SUFFIX)).unlink()
    announce(runs, str(control / ("a" * 5000)))
    not_delivered(dirs, FakeControl())  # larger than any announcement


def test_a_run_id_that_is_not_a_proxy_run_id_is_never_a_path(dirs: tuple[Path, Path]) -> None:
    runs, control = dirs
    fake = FakeControl()
    approver = approvals(dirs, fake)
    for run_id in ("../x", "mcp-xyz", "mcp-0123456789AB", "", RUN + "/.."):
        announce(runs, str(control / "a.sock"), run_id="mcp-ffffffffffff")
        assert approver.control_socket(run_id) is None
    assert fake.connects == []


# -- the app: flag and loopback --------------------------------------------------------------------


def serve_run(
    runs: Path, control: Path, fake: FakeControl, *, enabled: bool = True
) -> tuple[TestClient, Path]:
    """An app whose `mcp` source follows an unfinished chain of three events."""
    events = run_events(RUN, 3, finish=False)
    log = RunLog(runs, RUN)
    for entry in entries_of(events):
        log.write(entry)
    log.close()
    announce(runs, str(control / "a.sock"))
    approver = McpApprovals(runs, control_directory=control, connect=fake.connect)
    app = create_app(
        event_delay=0,
        sources={"mcp": McpRunsSource(runs, poll=lambda: None)},
        mcp_runs_dir=runs,
        mcp_approvals=approver if enabled else None,
    )
    return TestClient(app, client=LOCAL), runs


def send_decision(client: TestClient, headers: dict[str, str] | None = None) -> WebSocketDisconnect:
    """Watch the three events, send an approve and wait for the server to close the socket."""
    url = f"/ws/runs/{RUN}?lane=notary&mode=mcp"
    with client.websocket_connect(url, headers=dict(headers or {})) as ws:
        for _ in range(3):
            EVENT_ADAPTER.validate_json(ws.receive_text())
        ws.send_text(frame("approve"))
        while True:
            try:
                ws.receive_text()
            except WebSocketDisconnect as closed:
                return closed


def send_accepted_decision(
    client: TestClient, fake: FakeControl, headers: dict[str, str] | None = None
) -> None:
    """The same, for a decision that is forwarded: an accepted command leaves the socket open (the
    card is closed by the chain, not by the server), so wait for the fake proxy to have answered."""
    url = f"/ws/runs/{RUN}?lane=notary&mode=mcp"
    with client.websocket_connect(url, headers=dict(headers or {})) as ws:
        for _ in range(3):
            EVENT_ADAPTER.validate_json(ws.receive_text())
        ws.send_text(frame("approve"))
        assert fake.replied.wait(PATIENCE)


def test_with_the_flag_and_a_local_client_the_card_decision_reaches_the_proxy(
    dirs: tuple[Path, Path],
) -> None:
    runs, control = dirs
    fake = FakeControl()
    client, _ = serve_run(runs, control, fake)
    send_accepted_decision(client, fake)
    assert fake.received == [b'{"op": "approve", "endorsement_id": "e1"}\n']


def test_the_server_reads_the_flag_only_when_it_is_exactly_one(dirs: tuple[Path, Path]) -> None:
    runs, control = dirs
    assert Settings.from_env({}).mcp_approvals is False
    for raw in ("", "0", "true", "yes", "2"):
        assert Settings.from_env({"NOTARY_MCP_APPROVALS": raw}).mcp_approvals is False
    settings = Settings.from_env(
        {
            "NOTARY_MCP_APPROVALS": "1",
            "NOTARY_MCP_RUNS_DIR": str(runs),
            "NOTARY_MCP_CONTROL_DIR": str(control),
        }
    )
    assert settings.mcp_approvals is True
    assert settings.mcp_control_dir == control
    assert Settings.from_env({"NOTARY_MCP_CONTROL_DIR": ""}).mcp_control_dir is None


def test_without_the_flag_a_command_is_refused_and_nothing_is_forwarded(
    dirs: tuple[Path, Path],
) -> None:
    runs, control = dirs
    fake = FakeControl()
    client, _ = serve_run(runs, control, fake, enabled=False)
    closed = send_decision(client)
    assert (closed.code, closed.reason) == (4422, "command not supported on this socket")
    assert fake.connects == []


def test_the_settings_decide_whether_the_app_has_an_approver(dirs: tuple[Path, Path]) -> None:
    runs, control = dirs
    serve_run(runs, control, FakeControl())  # writes the chain and the announcement
    off = build_app(Settings(mcp_runs_dir=runs), event_delay=0)
    closed = send_decision(TestClient(off, client=LOCAL))
    assert (closed.code, closed.reason) == (4422, "command not supported on this socket")
    # on: the handler is there, and (nobody listens on the announced socket) it says so
    on = build_app(
        Settings(mcp_runs_dir=runs, mcp_approvals=True, mcp_control_dir=control), event_delay=0
    )
    closed = send_decision(TestClient(on, client=LOCAL))
    assert (closed.code, closed.reason) == (4409, REASON_NOT_DELIVERED)
    # the flag without a directory of runs has no mode mcp at all
    no_runs = build_app(Settings(mcp_approvals=True), event_delay=0)
    assert "mcp" not in TestClient(no_runs).get("/runs/modes").json()["modes"]


@pytest.mark.parametrize(
    ("peer", "headers"),
    [
        (("testclient", 50000), None),
        (("10.0.0.7", 50000), None),
        (("192.168.1.5", 1), None),
        (("::ffff:10.0.0.7", 1), None),
        (("127.0.0.1", 50000), {"x-forwarded-for": "203.0.113.9"}),
        (("127.0.0.1", 50000), {"forwarded": "for=203.0.113.9"}),
        (("127.0.0.1", 50000), {"origin": "http://evil.example"}),
        (("127.0.0.1", 50000), {"origin": "null"}),
    ],
)
def test_a_client_that_is_not_local_is_refused_and_nothing_is_forwarded(
    dirs: tuple[Path, Path], peer: tuple[str, int], headers: dict[str, str] | None
) -> None:
    runs, control = dirs
    fake = FakeControl()
    client, _ = serve_run(runs, control, fake)
    closed = send_decision(TestClient(client.app, client=peer), headers)
    assert (closed.code, closed.reason) == (4422, "command not supported on this socket")
    assert fake.connects == []


@pytest.mark.parametrize(
    ("peer", "headers"),
    [
        (("127.0.0.1", 1), None),
        (("127.5.5.5", 1), None),
        (("::1", 1), None),
        (("::ffff:127.0.0.1", 1), None),
        (("127.0.0.1", 1), {"origin": "http://localhost:3000"}),
    ],
)
def test_loopback_clients_and_the_xray_origin_are_heard(
    dirs: tuple[Path, Path], peer: tuple[str, int], headers: dict[str, str] | None
) -> None:
    runs, control = dirs
    fake = FakeControl()
    client, _ = serve_run(runs, control, fake)
    send_accepted_decision(TestClient(client.app, client=peer), fake, headers)
    assert len(fake.connects) == 1


def test_loopback_host_parsing() -> None:
    assert [is_loopback_host(h) for h in ("127.0.0.1", "::1", "::ffff:127.0.0.1")] == [True] * 3
    bad = (None, "", "localhost", "testclient", "0.0.0.0", "10.0.0.1", "::", "::ffff:10.0.0.1")
    assert [is_loopback_host(h) for h in bad] == [False] * len(bad)


def test_the_command_still_needs_the_socket_to_own_the_run(dirs: tuple[Path, Path]) -> None:
    runs, control = dirs
    fake = FakeControl()
    client, _ = serve_run(runs, control, fake)
    url = f"/ws/runs/{RUN}?lane=notary&mode=mcp"
    with client.websocket_connect(url) as ws:
        for _ in range(3):
            ws.receive_text()
        ws.send_text(frame("approve", run_id="mcp-ffffffffffff"))
        closed = until_closed(ws)
    assert (closed.code, closed.reason) == (4409, "command is for another run")
    assert fake.connects == []


# -- end to end: the real proxy, the toy bank, the app in process ----------------------------------


class ProxyProcess:
    """The proxy as a child process: JSON-RPC lines in, answers read by id, stderr collected."""

    def __init__(self, command: list[str]) -> None:
        self._process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        assert self._process.stdin is not None
        assert self._process.stdout is not None
        assert self._process.stderr is not None
        self._stdin = self._process.stdin
        self._lines: queue.Queue[bytes] = queue.Queue()
        self._answers: dict[object, JsonObject] = {}
        stdout, stderr = self._process.stdout, self._process.stderr
        self._errors: queue.Queue[bytes] = queue.Queue()
        self._pumps = [
            threading.Thread(target=self._pump, args=(stdout,), daemon=True),
            threading.Thread(target=self._pump_errors, args=(stderr,), daemon=True),
        ]
        for pump in self._pumps:
            pump.start()

    def _pump(self, stream: IO[bytes]) -> None:
        for raw in iter(stream.readline, b""):
            self._lines.put(raw)
        self._lines.put(b"")

    def _pump_errors(self, stream: IO[bytes]) -> None:
        for raw in iter(stream.readline, b""):
            self._errors.put(raw)

    def approval_code(self, endorsement_id: str) -> str:
        """The one-time code the proxy printed on stderr for this card (what the user reads)."""
        marker = f"approval code for {endorsement_id}: "
        while True:
            line = self._errors.get(timeout=PATIENCE).decode("utf-8")
            if marker in line:
                return line.split(marker, 1)[1].strip()

    def send(self, request_id: int, method: str, params: dict[str, object]) -> None:
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        self._stdin.write(json.dumps(message).encode("utf-8") + b"\n")
        self._stdin.flush()

    def result(self, request_id: int) -> JsonObject:
        while request_id not in self._answers:
            line = self._lines.get(timeout=PATIENCE)
            assert line, "the proxy closed stdout before answering"
            message = as_object(json.loads(line))
            assert message is not None
            self._answers[message.get("id")] = message
        answer = as_object(self._answers[request_id].get("result"))
        assert answer is not None
        return answer

    def finish(self) -> None:
        self._stdin.close()
        assert self._process.wait(timeout=PATIENCE) == 0
        for pump in self._pumps:
            pump.join(timeout=PATIENCE)


def bank_proxy(directory: Path, audit: Path, control: Path) -> ProxyProcess:
    data = json.loads((BANK / "notary.json").read_text())
    data["server"]["command"] = [sys.executable, str(BANK / "server.py")]
    config = directory / "notary.json"
    config.write_text(json.dumps(data))
    return ProxyProcess(
        [
            sys.executable,
            "-m",
            "notary_mcp_proxy",
            "--config",
            str(config),
            "--audit-dir",
            str(audit),
            "--control",
            str(control / "bank.sock"),
            "--approval-timeout",
            "60",
        ]
    )


def watch_until(
    ws: WebSocketTestSession, stop: Callable[[Event], bool], seen: list[Event]
) -> Event:
    while True:
        event = EVENT_ADAPTER.validate_json(ws.receive_text())
        seen.append(event)
        if stop(event):
            return event


@pytest.mark.parametrize("choice", ["approve", "reject"])
def test_the_card_decides_a_real_proxy_escalation(
    tmp_path_factory: pytest.TempPathFactory, choice: str
) -> None:
    directory = tmp_path_factory.mktemp("e2e")
    audit, control = directory / "runs", directory / "ctl"
    proxy = bank_proxy(directory, audit, control)
    proxy.send(1, "initialize", {"protocolVersion": "2025-06-18"})
    proxy.result(1)
    (announcement,) = audit.glob("*" + CONTROL_SUFFIX)  # written before the proxy answers
    run_id = announcement.name.removesuffix(CONTROL_SUFFIX)
    app = create_app(
        event_delay=0,
        sources={"mcp": McpRunsSource(audit, poll=lambda: None)},
        mcp_runs_dir=audit,
        mcp_approvals=McpApprovals(audit, control_directory=control),
    )
    proxy.send(2, "tools/call", {"name": "add_contact", "arguments": {"name": "Alpha Consulting"}})
    seen: list[Event] = []
    url = f"/ws/runs/{run_id}?lane=notary&mode=mcp"
    with TestClient(app, client=LOCAL).websocket_connect(url) as ws:
        watchdog = threading.Timer(PATIENCE, ws.close)
        watchdog.start()
        try:
            card = watch_until(ws, lambda e: e.type == "endorsement_requested", seen)
            assert isinstance(card, EndorsementRequested)
            # nothing has run: the call is waiting for the user
            assert not [e for e in seen if e.type == "effect_executed"]
            decision: dict[str, object] = {
                "type": "endorsement_decision",
                "run_id": run_id,
                "endorsement_id": card.endorsement.endorsement_id,
                "decision": choice,
            }
            if choice == "approve":  # the user types what the proxy printed in its own terminal
                decision["code"] = proxy.approval_code(card.endorsement.endorsement_id)
            ws.send_text(json.dumps(decision))
            answer = proxy.result(2)
            if choice == "approve":
                # the card resolves from the stream: a second decision, then the effect
                watch_until(ws, lambda e: e.type == "effect_executed", seen)
                assert answer["isError"] is False
                verdicts = [e.decision.verdict for e in seen if isinstance(e, DecisionMade)]
                assert verdicts[-2:] == ["ESCALATE", "ALLOW"]
            else:
                assert answer["isError"] is True
                assert "the user rejected the endorsement" in json.dumps(answer)
                assert not [e for e in seen if e.type == "effect_executed"]
        finally:
            watchdog.cancel()
    proxy.finish()
    assert not list(audit.glob("*" + CONTROL_SUFFIX))
