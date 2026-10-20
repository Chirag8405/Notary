"""The agent-side Streamable HTTP endpoint: auth, Origin, one session, the demo's verdicts.

Local sockets on 127.0.0.1 only, no network. Nothing sleeps: a test knows a call is in flight from
an event the backend sets, that a card is open from `desk.wait_for_open`, and that a run is over
from the serving thread ending.
"""

import http.client
import json
import sys
import threading
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest
from proxy_builders import RecordingBackend, make_gateway
from pydantic import JsonValue

from notary_core.models import DecisionMade, EffectExecuted, RunFinished
from notary_mcp_proxy import BackendResult
from notary_mcp_proxy.approvals import ApprovalDesk
from notary_mcp_proxy.client import StdioClient
from notary_mcp_proxy.config import ProxyConfig
from notary_mcp_proxy.control import ControlServer, send
from notary_mcp_proxy.http_client import HttpClient
from notary_mcp_proxy.http_server import AgentEndpoint, HttpSettings
from notary_mcp_proxy.jsonrpc import JsonObject, as_object
from notary_mcp_proxy.main import build_server
from notary_mcp_proxy.server import ProxyServer

PATIENCE = 30.0
"""Only a failing test waits this long."""
TOKEN = "0123456789abcdef0123456789abcdef"
BANK = Path(__file__).resolve().parents[1] / "examples" / "bank"
ACME_IBAN = "DE00ACME00000000000001"
ATTACKER_IBAN = "DE00ATTACKER0000000001"
JSON = "application/json"
BOTH = "application/json, text/event-stream"


@dataclass
class Reply:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> JsonObject:
        parsed = as_object(json.loads(self.body))
        assert parsed is not None
        return parsed

    def error_code(self) -> JsonValue:
        return (as_object(self.json().get("error")) or {}).get("code")


class Events:
    """The SSE stream of one reply: read the events one by one."""

    def __init__(self, connection: http.client.HTTPConnection, reply: http.client.HTTPResponse):
        self.connection = connection
        self.reply = reply

    def next(self) -> JsonObject | None:
        data: list[str] = []
        while True:
            line = self.reply.readline().decode("utf-8")
            if not line:
                return None
            text = line.rstrip("\r\n")
            if text.startswith("data:"):
                data.append(text[5:].lstrip())
            elif not text and data:
                parsed = as_object(json.loads("\n".join(data)))
                assert parsed is not None
                return parsed

    def close(self) -> None:
        self.reply.close()
        self.connection.close()


def initialize_message(capabilities: JsonObject | None = None) -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "id": "init",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": capabilities or {},
            "clientInfo": {"name": "scripted", "version": "0"},
        },
    }


def call_message(request_id: JsonValue, name: str, arguments: JsonObject) -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


class BlockingBackend(RecordingBackend):
    """`read_inbox` waits until the test lets it go."""

    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def call_tool(self, tool: str, args: Mapping[str, str]) -> BackendResult:
        if tool == "read_inbox":
            self.entered.set()
            self.release.wait(PATIENCE)
        return super().call_tool(tool, args)


class Rig:
    """A `ProxyServer` served over HTTP on a free loopback port, and a scripted agent."""

    def __init__(
        self,
        server: ProxyServer,
        *,
        origins: frozenset[str] = frozenset(),
        control: ControlServer | None = None,
        desk: ApprovalDesk | None = None,
    ) -> None:
        self.server = server
        self.control = control
        self.desk = desk
        self.endpoint = AgentEndpoint(
            HttpSettings(token=TOKEN.encode(), port=0, allowed_origins=origins)
        )
        self.host, self.port = self.endpoint.address
        self.thread = threading.Thread(target=self.endpoint.serve, args=(server,), daemon=True)
        self.thread.start()
        self.session: str | None = None

    def raw(
        self,
        verb: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        token: str | None = TOKEN,
        session: str | None = None,
        content_type: str | None = JSON,
        accept: str | None = BOTH,
        path: str = "/mcp",
    ) -> Reply:
        send_headers: dict[str, str] = {}
        if token is not None:
            send_headers["Authorization"] = f"Bearer {token}"
        if content_type is not None and body is not None:
            send_headers["Content-Type"] = content_type
        if accept is not None:
            send_headers["Accept"] = accept
        if session is not None:
            send_headers["Mcp-Session-Id"] = session
        send_headers.update(headers or {})
        connection = http.client.HTTPConnection(self.host, self.port, timeout=PATIENCE)
        try:
            connection.request(verb, path, body, send_headers)
            reply = connection.getresponse()
            data = reply.read()
            return Reply(reply.status, {k.lower(): v for k, v in reply.getheaders()}, data)
        finally:
            connection.close()

    def post(
        self,
        message: JsonValue,
        *,
        session: str | None = None,
        use_session: bool = True,
        headers: Mapping[str, str] | None = None,
        token: str | None = TOKEN,
        accept: str | None = BOTH,
        content_type: str | None = JSON,
    ) -> Reply:
        return self.raw(
            "POST",
            body=json.dumps(message).encode("utf-8"),
            session=(session or self.session) if use_session else None,
            headers=headers,
            token=token,
            accept=accept,
            content_type=content_type,
        )

    def open_stream(self, message: JsonObject, *, accept: str = BOTH) -> Events:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=PATIENCE)
        headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": JSON, "Accept": accept}
        if self.session is not None:
            headers["Mcp-Session-Id"] = self.session
        connection.request("POST", "/mcp", json.dumps(message).encode("utf-8"), headers)
        reply = connection.getresponse()
        assert reply.status == 200
        assert reply.getheader("Content-Type") == "text/event-stream"
        return Events(connection, reply)

    def get_stream(self) -> Events:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=PATIENCE)
        headers = {"Authorization": f"Bearer {TOKEN}", "Accept": "text/event-stream"}
        assert self.session is not None
        headers["Mcp-Session-Id"] = self.session
        connection.request("GET", "/mcp", headers=headers)
        reply = connection.getresponse()
        assert reply.status == 200
        return Events(connection, reply)

    def start(self, capabilities: JsonObject | None = None) -> str:
        reply = self.post(initialize_message(capabilities), use_session=False)
        assert reply.status == 200, reply.body
        self.session = reply.headers["mcp-session-id"]
        assert self.post({"jsonrpc": "2.0", "method": "notifications/initialized"}).status == 202
        return self.session

    def stop(self) -> None:
        self.endpoint.stop()
        self.thread.join(PATIENCE)
        assert not self.thread.is_alive()

    def close(self) -> None:
        self.stop()
        if self.control is not None:
            self.control.close()
        self.endpoint.close()

    def verdicts(self) -> list[str]:
        return [
            e.event.decision.verdict
            for e in self.server.gateway.chain
            if isinstance(e.event, DecisionMade)
        ]


Make = Callable[..., Rig]


@pytest.fixture
def make(tmp_path: Path) -> Iterator[Make]:
    rigs: list[Rig] = []

    def build(
        *,
        backend: RecordingBackend | None = None,
        origins: frozenset[str] = frozenset(),
        control: bool = False,
    ) -> Rig:
        used = backend or RecordingBackend()
        gateway = make_gateway(used)
        desk = ApprovalDesk(timeout_seconds=120.0, poll_seconds=0.005)
        server = ProxyServer(gateway, [], desk)
        socket_control = None
        if control:
            socket_control = ControlServer(desk, tmp_path / "c" / "p.sock")
            socket_control.start()
        rig = Rig(server, origins=origins, control=socket_control, desk=desk)
        rigs.append(rig)
        return rig

    yield build
    for rig in rigs:
        rig.close()


# -- authentication, Origin, Host --


def test_no_token_is_401_and_nothing_runs(make: Make, capsys: pytest.CaptureFixture[str]) -> None:
    rig = make()
    reply = rig.post(initialize_message(), token=None)
    assert reply.status == 401
    assert reply.headers["www-authenticate"].startswith("Bearer")
    assert reply.error_code() == -32600
    assert rig.server.gateway.chain == ()
    assert TOKEN not in capsys.readouterr().err
    assert rig.start()  # a good request still opens the session: the refusal changed nothing


@pytest.mark.parametrize(
    "header",
    ["Bearer wrong", "Bearer ", "Bearer", "Basic " + "0123456789abcdef0123456789abcdef", "", TOKEN],
)
def test_a_wrong_or_malformed_token_is_401(make: Make, header: str) -> None:
    rig = make()
    reply = rig.post(initialize_message(), token=None, headers={"Authorization": header})
    assert reply.status == 401


def test_a_token_that_is_a_prefix_or_an_extension_is_refused(make: Make) -> None:
    rig = make()
    assert rig.post(initialize_message(), token=TOKEN[:-1]).status == 401
    assert rig.post(initialize_message(), token=TOKEN + "x").status == 401
    assert rig.post(initialize_message(), token=TOKEN.upper()).status == 401


def test_the_scheme_is_case_insensitive(make: Make) -> None:
    rig = make()
    reply = rig.post(initialize_message(), token=None, headers={"Authorization": f"bearer {TOKEN}"})
    assert reply.status == 200


def test_get_and_delete_need_the_token_too(make: Make) -> None:
    rig = make()
    rig.start()
    assert rig.raw("GET", token=None, session=rig.session, accept="text/event-stream").status == 401
    assert rig.raw("DELETE", token=None, session=rig.session).status == 401
    assert rig.thread.is_alive()  # the refused DELETE did not end the run


def test_a_bad_origin_is_403_even_with_the_right_token(make: Make) -> None:
    rig = make()
    for origin in ("http://evil.example", "null", "http://127.0.0.1:" + str(rig.port)):
        reply = rig.post(initialize_message(), headers={"Origin": origin})
        assert reply.status == 403, origin
    assert rig.server.gateway.chain == ()


def test_an_allowed_origin_and_no_origin_are_accepted(make: Make) -> None:
    rig = make(origins=frozenset({"http://localhost:3000"}))
    allowed = {"Origin": "http://localhost:3000"}
    first = rig.post(initialize_message(), headers=allowed, use_session=False)
    assert first.status == 200
    rig.session = first.headers["mcp-session-id"]
    ping: JsonObject = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert rig.post(ping, headers=allowed).status == 200
    assert rig.post(ping).status == 200  # no Origin: a command-line client
    assert rig.post(ping, headers={"Origin": "http://localhost:3001"}).status == 403


def test_a_foreign_host_header_is_403(make: Make) -> None:
    """DNS rebinding: the browser's Host is the attacker's name, whatever the address."""
    rig = make()
    for host in ("evil.example", f"evil.example:{rig.port}", f"127.0.0.1:{rig.port + 1}"):
        reply = rig.post(initialize_message(), headers={"Host": host})
        assert reply.status == 403, host
    assert rig.post(initialize_message(), headers={"Host": f"localhost:{rig.port}"}).status == 200


# -- one session --


def test_the_first_initialize_makes_the_session_and_a_second_is_refused(make: Make) -> None:
    rig = make()
    first = rig.post(initialize_message(), use_session=False)
    assert first.status == 200
    session = first.headers["mcp-session-id"]
    assert len(session) >= 32
    result = as_object(first.json()["result"]) or {}
    assert result["protocolVersion"] == "2025-06-18"
    # Another client, with no session, with another session, and with the first one: all refused.
    assert rig.post(initialize_message(), use_session=False).status == 409
    assert rig.post(initialize_message(), session="some-other-session").status == 409
    assert rig.post(initialize_message(), session=session).status == 409
    refused = rig.post(initialize_message(), use_session=False)
    assert "mcp-session-id" not in refused.headers
    assert refused.error_code() == -32600


def test_requests_need_the_session_id(make: Make) -> None:
    rig = make()
    ping: JsonObject = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert rig.post(ping, use_session=False).status == 400  # no session, no header
    assert rig.post(ping, session="made-up").status == 404  # before any initialize
    rig.start()
    assert rig.post(ping, use_session=False).status == 400
    assert rig.post(ping, session="made-up").status == 404
    assert rig.post(ping).status == 200
    assert rig.post(ping).json() == {"jsonrpc": "2.0", "id": 1, "result": {}}


def test_unsupported_protocol_version_is_400(make: Make) -> None:
    rig = make()
    rig.start()
    ping: JsonObject = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert rig.post(ping, headers={"MCP-Protocol-Version": "1999-01-01"}).status == 400
    assert rig.post(ping, headers={"MCP-Protocol-Version": "2025-06-18"}).status == 200


# -- malformed requests --


def test_bad_requests_are_refused_with_fixed_texts(make: Make) -> None:
    rig = make()
    rig.start()
    ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
    assert rig.raw("POST", body=ping, session=rig.session, content_type="text/plain").status == 415
    assert rig.raw("POST", body=ping, session=rig.session, content_type=None).status == 415
    assert rig.raw("POST", body=b"{nope", session=rig.session).status == 400
    assert rig.raw("POST", body=b"[1]", session=rig.session).status == 400  # no batches
    assert rig.raw("POST", body=b"7", session=rig.session).status == 400
    assert rig.raw("POST", body=ping, session=rig.session, path="/other").status == 404
    declared = {"Content-Length": str(5 << 20)}  # refused on the header, before any body is read
    assert rig.raw("POST", body=b"{}", session=rig.session, headers=declared).status == 413
    bad_ids = ["true", "null", "[1]", '{"a":1}', "1.5"]
    for bad_id in bad_ids:
        text = f'{{"jsonrpc":"2.0","id":{bad_id},"method":"ping"}}'.encode()
        assert rig.raw("POST", body=text, session=rig.session).status == 400, bad_id
    assert rig.post(json.loads(ping), accept="text/plain").status == 406
    assert rig.post(json.loads(ping)).status == 200  # none of that disturbed the session


def test_get_needs_an_event_stream_accept_and_one_stream_at_a_time(make: Make) -> None:
    rig = make()
    rig.start()
    assert rig.raw("GET", session=rig.session, accept=JSON).status == 406
    stream = rig.get_stream()
    try:
        second = rig.raw("GET", session=rig.session, accept="text/event-stream")
        assert second.status == 409
    finally:
        stream.close()


def test_notifications_and_client_responses_are_accepted_with_202(make: Make) -> None:
    rig = make()
    rig.start()
    assert rig.post({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}).status == 202
    assert rig.post({"jsonrpc": "2.0", "id": "n99", "result": {}}).status == 202  # stray answer


# -- the proxy behind it is the same proxy --


def _bank_proxy(tmp_path: Path, clients: list[StdioClient]) -> ProxyServer:
    data = json.loads((BANK / "notary.json").read_text())
    data["server"]["command"] = [sys.executable, str(BANK / "server.py")]
    config = ProxyConfig.model_validate_json(json.dumps(data))
    client = StdioClient(config.server.command)
    clients.append(client)
    return build_server(config, client, run_id="run-test")


@pytest.fixture
def bank_clients() -> Iterator[list[StdioClient]]:
    started: list[StdioClient] = []
    yield started
    for client in started:
        client.close()


def _result(answer: JsonObject) -> JsonObject:
    found = as_object(answer["result"])
    assert found is not None
    return found


@pytest.mark.attack("A3")
def test_the_demo_through_http_has_the_same_verdicts_and_texts_as_stdio(
    tmp_path: Path, bank_clients: list[StdioClient]
) -> None:
    direct = _bank_proxy(tmp_path, bank_clients)
    served = _bank_proxy(tmp_path, bank_clients)
    rig = Rig(served)
    try:
        client = HttpClient(
            rig.endpoint.url, headers={"Authorization": f"Bearer {TOKEN}"}, timeout_seconds=PATIENCE
        )
        client.initialize()
        tools = client.list_tools()
        assert sorted(str(t["name"]) for t in tools) == ["add_contact", "pay_bill", "read_inbox"]
        calls: list[tuple[str, JsonObject]] = [
            ("read_inbox", {}),
            ("pay_bill", {"payee": ATTACKER_IBAN, "amount": 120}),
            ("pay_bill", {"payee": ACME_IBAN, "amount": 120}),
        ]
        for index, (name, arguments) in enumerate(calls, start=1):
            over_http = client.call_tool(name, arguments)
            answer = direct.handle(call_message(index, name, arguments))
            assert answer is not None
            in_process = _result(answer)
            assert over_http == in_process, name
        client.close()  # DELETE: the session and the run end
        rig.thread.join(PATIENCE)
        assert not rig.thread.is_alive()
    finally:
        rig.close()
    assert rig.verdicts() == ["ALLOW", "BLOCK", "ALLOW"]
    chain = served.gateway.chain
    served.finish_run()
    blocked = [
        e.event.decision
        for e in chain
        if isinstance(e.event, DecisionMade) and e.event.call_id == "c2"
    ]
    assert "LEDGER_NOT_FOUND" in [reason.code for reason in blocked[0].reasons]
    assert [e.event.tool for e in chain if isinstance(e.event, EffectExecuted)] == [
        "read_inbox",
        "pay_bill",
    ]
    last = served.gateway.chain[-1].event
    assert isinstance(last, RunFinished)
    assert "closed by the agent after 3 tool calls" in last.summary
    # The audit chain is the stdio chain: same events in the same order.
    direct.finish_run()
    assert [e.event.type for e in served.gateway.chain] == [
        e.event.type for e in direct.gateway.chain
    ]


def test_delete_ends_the_run_and_the_listener(make: Make) -> None:
    rig = make()
    rig.start()
    assert rig.raw("DELETE", session=rig.session).status == 200
    rig.thread.join(PATIENCE)
    assert not rig.thread.is_alive()
    rig.server.finish_run()
    assert isinstance(rig.server.gateway.chain[-1].event, RunFinished)


def test_delete_with_another_session_id_does_not_end_the_run(make: Make) -> None:
    rig = make()
    rig.start()
    assert rig.raw("DELETE", session="not-the-session").status == 404
    assert rig.thread.is_alive()
    assert rig.post({"jsonrpc": "2.0", "id": 1, "method": "ping"}).status == 200


def test_unknown_methods_are_json_rpc_errors_and_calls_keep_their_order(make: Make) -> None:
    backend = RecordingBackend()
    rig = make(backend=backend)
    rig.start()
    unknown = rig.post({"jsonrpc": "2.0", "id": 5, "method": "nope/never"}).json()
    assert as_object(unknown["error"]) == {
        "code": -32601,
        "message": "method not found: nope/never",
    }
    for index in (3, 1, 2):
        reply = rig.post(call_message(index, "read_inbox", {}), accept=JSON)
        assert reply.status == 200
        assert reply.json()["id"] == index
    assert [name for name, _ in backend.calls] == ["read_inbox"] * 3
    assert [
        e.event.call_id for e in rig.server.gateway.chain if isinstance(e.event, DecisionMade)
    ] == [
        "c1",
        "c2",
        "c3",
    ]


# -- server-to-client messages over HTTP --


def test_elicitation_travels_on_the_calls_own_stream(make: Make) -> None:
    backend = RecordingBackend()
    rig = make(backend=backend)
    rig.start({"elicitation": {}})
    stream = rig.open_stream(call_message(7, "add_contact", {"name": "Alpha Consulting"}))
    try:
        asked = stream.next()
        assert asked is not None
        assert asked["method"] == "elicitation/create"
        assert backend.calls == []  # waiting for the user
        approved: JsonObject = {"action": "accept", "content": {"decision": "approve"}}
        answer: JsonObject = {"jsonrpc": "2.0", "id": asked["id"], "result": approved}
        assert rig.post(answer).status == 202
        final = stream.next()
        assert final is not None
        assert final["id"] == 7
        assert _result(final)["isError"] is False
        assert stream.next() is None  # the stream ends with the answer
    finally:
        stream.close()
    assert backend.calls == [("add_contact", {"name": "Alpha Consulting"})]
    assert rig.verdicts() == ["ESCALATE", "ALLOW"]


def test_elicitation_travels_on_the_standalone_stream_when_one_is_open(make: Make) -> None:
    backend = RecordingBackend()
    rig = make(backend=backend)
    rig.start({"elicitation": {}})
    standalone = rig.get_stream()
    try:
        outcome: list[Reply] = []
        caller = threading.Thread(
            target=lambda: outcome.append(
                rig.post(call_message(8, "add_contact", {"name": "Alpha Consulting"}), accept=JSON)
            )
        )
        caller.start()
        asked = standalone.next()
        assert asked is not None
        assert asked["method"] == "elicitation/create"
        rejected: JsonObject = {"action": "decline"}
        assert rig.post({"jsonrpc": "2.0", "id": asked["id"], "result": rejected}).status == 202
        caller.join(PATIENCE)
        assert not caller.is_alive()
    finally:
        standalone.close()
    assert outcome[0].status == 200
    assert _result(outcome[0].json())["isError"] is True  # declined: the call did not run
    assert backend.calls == []


def test_without_a_stream_the_card_waits_on_the_control_socket(make: Make) -> None:
    backend = RecordingBackend()
    rig = make(backend=backend, control=True)
    rig.start({"elicitation": {}})
    assert rig.control is not None
    outcome: list[Reply] = []
    caller = threading.Thread(
        target=lambda: outcome.append(
            rig.post(call_message(9, "add_contact", {"name": "Alpha Consulting"}), accept=JSON)
        )
    )
    caller.start()
    assert rig.desk is not None
    assert rig.desk.wait_for_open(1)
    assert send(rig.control.path, {"op": "approve", "endorsement_id": "e1"}).get("ok") is True
    caller.join(PATIENCE)
    assert not caller.is_alive()
    assert _result(outcome[0].json())["isError"] is False
    assert backend.calls == [("add_contact", {"name": "Alpha Consulting"})]


def test_the_agent_cancelling_a_call_ends_its_reply(make: Make) -> None:
    backend = BlockingBackend()
    rig = make(backend=backend)
    rig.start()
    outcome: list[Reply] = []
    caller = threading.Thread(
        target=lambda: outcome.append(rig.post(call_message(11, "read_inbox", {}), accept=JSON))
    )
    caller.start()
    assert backend.entered.wait(PATIENCE)  # the call is running
    cancel: JsonObject = {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 11, "reason": "user"},
    }
    assert rig.post(cancel).status == 202
    caller.join(PATIENCE)
    assert not caller.is_alive()  # the reply ended without waiting for the backend
    assert outcome[0].error_code() == -32800
    backend.release.set()
    rig.stop()
    # The logged decision stays in the chain; the cancelled call gets no result of its own.
    assert rig.verdicts() == ["ALLOW"]


def test_closing_the_run_while_a_call_runs_lets_it_finish(make: Make) -> None:
    backend = BlockingBackend()
    rig = make(backend=backend)
    rig.start()
    outcome: list[Reply] = []
    caller = threading.Thread(
        target=lambda: outcome.append(rig.post(call_message(12, "read_inbox", {}), accept=JSON))
    )
    caller.start()
    assert backend.entered.wait(PATIENCE)
    assert rig.raw("DELETE", session=rig.session).status == 200
    backend.release.set()
    caller.join(PATIENCE)
    rig.thread.join(PATIENCE)
    assert not rig.thread.is_alive()
    assert outcome[0].status == 200  # the call in progress finished and was answered
    assert rig.verdicts() == ["ALLOW"]
