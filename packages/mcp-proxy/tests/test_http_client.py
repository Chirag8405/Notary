"""The downstream Streamable HTTP client against local stdlib servers (no network).

The only waits are the client's own tiny timeouts against a handler that never answers.
"""

import socket
from collections.abc import Callable, Iterator
from typing import Unpack

import pytest
from http_fake import FakeHttpServer, FakeOptions, Seen, tool

from notary_mcp_proxy.client import (
    PROTOCOL_VERSION,
    McpClient,
    ServerError,
    ServerExitedError,
    ServerRejectedError,
    ServerTimeoutError,
)
from notary_mcp_proxy.http_client import HttpClient
from notary_mcp_proxy.jsonrpc import JsonObject, as_object

TIGHT = 0.3
"""A call to a handler that never answers is given this long."""


@pytest.fixture
def servers() -> Iterator[list[FakeHttpServer]]:
    started: list[FakeHttpServer] = []
    yield started
    for server in started:
        server.close()


@pytest.fixture
def clients() -> Iterator[list[HttpClient]]:
    started: list[HttpClient] = []
    yield started
    for client in started:
        client.close()


Make = Callable[..., tuple[FakeHttpServer, HttpClient]]


@pytest.fixture
def make(servers: list[FakeHttpServer], clients: list[HttpClient]) -> Make:
    def build(
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 5.0,
        initialize: bool = True,
        tools: list[JsonObject] | None = None,
        **options: Unpack[FakeOptions],
    ) -> tuple[FakeHttpServer, HttpClient]:
        server = FakeHttpServer(
            tools if tools is not None else [tool("lookup"), tool("slow")], **options
        )
        servers.append(server)
        client = HttpClient(server.url, headers=headers, timeout_seconds=timeout)
        clients.append(client)
        if initialize:
            client.initialize()
        return server, client

    return build


def _posts(server: FakeHttpServer) -> list[Seen]:
    return [item for item in server.seen if item.verb == "POST"]


def test_the_http_client_is_an_mcp_client(make: Make) -> None:
    _, client = make()
    assert isinstance(client, McpClient)


def test_handshake_headers_and_session(make: Make) -> None:
    server, client = make(headers={"Authorization": "Bearer abc"})
    assert client.session_id == "sess-1"
    first, initialized, *_ = _posts(server)
    assert first.method == "initialize"
    assert first.headers["accept"] == "application/json, text/event-stream"
    assert first.headers["content-type"] == "application/json"
    assert first.headers["authorization"] == "Bearer abc"
    assert "mcp-session-id" not in first.headers  # no session yet
    assert "mcp-protocol-version" not in first.headers
    params = as_object(first.body and first.body.get("params")) or {}
    assert params["protocolVersion"] == PROTOCOL_VERSION
    # Every request after the handshake carries the session and the negotiated version.
    assert initialized.method == "notifications/initialized"
    assert initialized.headers["mcp-session-id"] == "sess-1"
    assert initialized.headers["mcp-protocol-version"] == PROTOCOL_VERSION
    assert initialized.headers["authorization"] == "Bearer abc"
    client.list_tools()
    client.call_tool("lookup", {})
    for item in _posts(server)[1:]:
        assert item.headers["mcp-session-id"] == "sess-1"
        assert item.headers["mcp-protocol-version"] == PROTOCOL_VERSION


def test_a_server_without_sessions_is_fine(make: Make) -> None:
    server, client = make(session_id=None)
    assert client.session_id is None
    client.list_tools()
    assert all("mcp-session-id" not in item.headers for item in _posts(server))
    client.close()
    assert "DELETE" not in server.methods()


def test_the_negotiated_version_is_the_one_sent(make: Make) -> None:
    server, client = make(version="2025-03-26")
    client.list_tools()
    assert _posts(server)[-1].headers["mcp-protocol-version"] == "2025-03-26"


def test_an_unknown_protocol_version_fails_the_handshake(
    servers: list[FakeHttpServer], clients: list[HttpClient]
) -> None:
    server = FakeHttpServer([tool("lookup")], version="1999-01-01")
    servers.append(server)
    client = HttpClient(server.url)
    clients.append(client)
    with pytest.raises(ServerError, match="broke the protocol"):
        client.initialize()


def test_tools_list_follows_pages_and_call_returns_the_result(make: Make) -> None:
    server, client = make(tools=[tool("a"), tool("b"), tool("c")], page_size=2)
    assert [entry["name"] for entry in client.list_tools()] == ["a", "b", "c"]
    assert len(server.requests("tools/list")) == 2
    answer = client.call_tool("b", {"x": 1})
    assert answer["isError"] is False
    call = server.requests("tools/call")[0]
    assert (as_object(call.body and call.body.get("params")) or {})["arguments"] == {"x": 1}


def test_the_whole_definition_is_kept(make: Make) -> None:
    extra: JsonObject = {**tool("lookup"), "x-vendor": {"k": 1}, "annotations": {"a": True}}
    _, client = make(tools=[extra])
    assert client.list_tools() == [extra]


def test_sse_answer_with_notifications_and_a_refused_server_request(make: Make) -> None:
    server, client = make(behaviors={"lookup": "sse_notify", "slow": "sse_request"})
    seen: list[tuple[str, JsonObject]] = []
    client.on_notification = lambda method, params: seen.append((method, params))
    assert client.call_tool("lookup", {})["isError"] is False
    assert seen == [("notifications/tools/list_changed", {})]
    assert client.call_tool("slow", {})["isError"] is False
    refusal = next(
        item.body
        for item in _posts(server)
        if item.body is not None and item.body.get("id") == "srv-1"
    )
    assert as_object(refusal["error"]) == {"code": -32601, "message": "not supported"}
    assert "method" not in refusal


def test_sse_without_notifications(make: Make) -> None:
    _, client = make(sse=["lookup"])
    assert client.call_tool("lookup", {})["content"] == [{"type": "text", "text": "lookup ok"}]


def test_timeout_cancels_and_the_next_request_works(make: Make) -> None:
    server, client = make(behaviors={"slow": "hang"})
    client.timeout_seconds = TIGHT
    with pytest.raises(ServerTimeoutError) as raised:
        client.call_tool("slow", {})
    assert str(raised.value) == "the server did not answer in time"
    assert server.arrived.is_set()
    call = server.requests("tools/call")[0]
    cancelled = server.requests("notifications/cancelled")
    assert len(cancelled) == 1  # sent before request() raised
    cancel_params = as_object(cancelled[0].body and cancelled[0].body.get("params")) or {}
    assert cancel_params["requestId"] == (call.body or {})["id"]
    assert cancel_params["reason"] == "timeout"
    assert client.alive
    client.timeout_seconds = 5.0
    assert client.call_tool("lookup", {})["isError"] is False  # no stale answer mixes in


def test_a_json_rpc_error_is_a_labeled_error_without_the_text(make: Make) -> None:
    _, client = make(behaviors={"lookup": "rpc_error"})
    with pytest.raises(ServerRejectedError) as raised:
        client.call_tool("lookup", {})
    assert str(raised.value) == "the server answered with an error"
    assert "IGNORE PREVIOUS INSTRUCTIONS" in raised.value.detail  # stderr only, quoted
    assert "\n" not in raised.value.detail


def test_is_error_result_is_returned_for_the_caller_to_label(make: Make) -> None:
    _, client = make(behaviors={"lookup": "error"})
    assert client.call_tool("lookup", {})["isError"] is True


@pytest.mark.parametrize("behavior", ["http500", "html", "bad_json", "short_stream"])
def test_protocol_and_status_failures_are_server_errors(make: Make, behavior: str) -> None:
    _, client = make(behaviors={"lookup": behavior})
    with pytest.raises(ServerError) as raised:
        client.call_tool("lookup", {})
    assert str(raised.value) in {
        "the server answered with an error",
        "the server broke the protocol",
    }
    assert "ignore previous" not in str(raised.value)
    assert client.alive  # one bad answer does not end the session


def test_status_failure_keeps_the_text_in_the_detail(make: Make) -> None:
    _, client = make(behaviors={"lookup": "http500"})
    with pytest.raises(ServerRejectedError) as raised:
        client.call_tool("lookup", {})
    assert "HTTP 500" in raised.value.detail


def test_a_wrong_token_is_a_rejection(make: Make) -> None:
    _, client = make(
        initialize=False,
        headers={"Authorization": "Bearer wrong"},
        require={"Authorization": "Bearer right"},
    )
    with pytest.raises(ServerRejectedError) as raised:
        client.initialize()
    assert "HTTP 401" in raised.value.detail
    assert "wrong" not in raised.value.detail
    assert "right" not in raised.value.detail


def test_a_forgotten_session_ends_the_client_for_good(make: Make) -> None:
    server, client = make(behaviors={"lookup": "forget"})
    with pytest.raises(ServerExitedError) as raised:
        client.call_tool("lookup", {})
    assert str(raised.value) == "the server is not running"
    assert not client.alive
    requests_before = len(server.seen)
    with pytest.raises(ServerExitedError):
        client.list_tools()  # not even tried: a new session would re-pin
    assert len(server.seen) == requests_before


def test_connection_refused_is_exited_and_retried_next_time(
    clients: list[HttpClient],
) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    client = HttpClient(f"http://127.0.0.1:{port}/mcp", timeout_seconds=2.0)
    clients.append(client)
    with pytest.raises(ServerExitedError) as raised:
        client.initialize()
    assert str(raised.value) == "the server is not running"
    assert client.alive


def test_redirects_are_not_followed(
    servers: list[FakeHttpServer], clients: list[HttpClient]
) -> None:
    elsewhere = FakeHttpServer([tool("lookup")])
    servers.append(elsewhere)
    server = FakeHttpServer([tool("lookup")], redirect_to=elsewhere.url)
    servers.append(server)
    client = HttpClient(server.url, headers={"Authorization": "Bearer secret"})
    clients.append(client)
    with pytest.raises(ServerRejectedError) as raised:
        client.initialize()
    assert "HTTP 307" in raised.value.detail
    assert elsewhere.seen == []  # the token went nowhere else


def test_close_ends_the_session_with_a_delete(make: Make) -> None:
    server, client = make()
    client.close()
    deletes = [item for item in server.seen if item.verb == "DELETE"]
    assert len(deletes) == 1
    assert deletes[0].headers["mcp-session-id"] == "sess-1"
    assert not client.alive
    client.close()  # idempotent
    assert len([item for item in server.seen if item.verb == "DELETE"]) == 1
    with pytest.raises(ServerExitedError):
        client.list_tools()


def test_a_server_that_refuses_delete_is_not_an_error(make: Make) -> None:
    server, client = make(delete_status=405)
    client.close()
    assert "DELETE" in server.methods()


def test_a_page_loop_is_a_protocol_error(make: Make) -> None:
    _, client = make(tools=[tool("a")], page_size=0)  # never advances
    with pytest.raises(ServerError, match="broke the protocol"):
        client.list_tools()
