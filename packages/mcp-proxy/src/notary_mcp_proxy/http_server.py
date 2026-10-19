"""The proxy served over MCP Streamable HTTP (spec 2025-06-18), for agents that do not spawn it.

`serve --http 127.0.0.1:8765 --token-file PATH` listens on one endpoint, `/mcp`, with the standard
library only (`http.server`, one thread per connection). Everything behind it is the stdio proxy,
unchanged: the endpoint is a transport for the same `Dispatcher` (reader thread, ONE worker thread
that owns the Gateway, cancellation, `ask_client`), the same `ProxyServer`, the same verdict texts
and the same audit chain. The two sides are joined with two OS pipes, so the dispatcher still
reads and writes newline-delimited JSON as it does on stdin and stdout and stays untouched:

    HTTP POST --> parse --> input pipe --> Dispatcher --> output pipe --> route by id --> HTTP reply

Security (this is a network-facing surface; threat-model.md):

- it binds to loopback by default and refuses another address unless `allow_remote_bind` is given;
- every request needs `Authorization: Bearer <token>`, compared in constant time; the token is
  read from a file that only its owner may access, is never logged and is not accepted from the
  command line;
- when bound to loopback the `Host` header must name this machine and this port, and an `Origin`
  header, if present, must be in `allowed_origins` (empty by default: a browser page is refused),
  so a page cannot reach the proxy through DNS rebinding or a cross-site request;
- `Content-Type: application/json` is required for a POST (a cross-site form cannot send it
  without a preflight), bodies are bounded, and a failed check answers a fixed text.

One session per proxy run: the first `initialize` creates it (`Mcp-Session-Id`), a second one is
refused with 409, and `DELETE /mcp` ends the session and the run (as closing stdin does for stdio:
the call in progress finishes, queued calls are dropped, `run_finished` is appended).

Replies. A request that is answered at once (`initialize`, `ping`, `tools/list`) gets a JSON body.
A queued request (`tools/call`, resources, `prompts/get`) gets an SSE stream when the client accepts
`text/event-stream`, so the proxy's own requests to the client (elicitation of an approval,
`notifications/cancelled`) can travel on it before the final answer; otherwise a JSON body. A
standalone `GET /mcp` stream, if the client opens one, carries those messages instead. With no
stream open a message for the client is dropped (the call then waits on the control socket for its
approval, as it does for any client that cannot elicit). `notifications/cancelled` for a request in
flight ends that request's HTTP reply with a JSON-RPC error (the client has stopped waiting).
"""

import hmac
import http.client
import json
import os
import queue
import secrets
import socket
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from typing import IO, ClassVar, override

from pydantic import JsonValue

from notary_mcp_proxy.client import SUPPORTED_VERSIONS, diagnostic
from notary_mcp_proxy.dispatch import CANCELLED, Dispatcher
from notary_mcp_proxy.hosts import is_loopback_host
from notary_mcp_proxy.jsonrpc import (
    INVALID_REQUEST,
    PARSE_ERROR,
    JsonObject,
    MessageError,
    as_object,
    as_str,
    error,
    read_message,
)
from notary_mcp_proxy.server import ProxyServer

ENDPOINT = "/mcp"
DEFAULT_BIND = "127.0.0.1:8765"
MAX_BODY_BYTES = 4 * 1024 * 1024
MIN_TOKEN_CHARS = 16
CONNECTION_TIMEOUT = 30.0
"""Seconds a connection may stall on a read or write (a slow client cannot hold a thread)."""
KEEPALIVE_SECONDS = 15.0
"""A standalone GET stream gets a comment line this often, so a dead client is noticed."""
REQUEST_CANCELLED = -32800
"""JSON-RPC code of the reply to a request the client cancelled (MCP schema: RequestCancelled)."""
SESSION_HEADER = "Mcp-Session-Id"
VERSION_HEADER = "MCP-Protocol-Version"
_TOKEN_CHARS = frozenset(chr(code) for code in range(0x21, 0x7F))


class TokenFileError(ValueError):
    """The token file cannot be used. The message never holds the token."""


class BindError(ValueError):
    """The `--http` address is not acceptable."""


def read_token_file(path: str) -> bytes:
    """The bearer token in `path`.

    The file must be a regular file that neither the group nor others can access (mode 0600 or
    0400): a token that others can read is not a secret. The token is the file's content without
    surrounding whitespace, 16 to 4096 visible ASCII characters (`openssl rand -hex 32` is right).
    """
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except OSError as failure:
        raise TokenFileError(f"cannot open the token file: {failure.strerror}") from failure
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise TokenFileError("the token file is not a regular file")
        if info.st_mode & 0o077:
            raise TokenFileError(
                "the token file is accessible by group or others "
                f"(mode {info.st_mode & 0o777:03o}); run: chmod 600 on it"
            )
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    text = raw.decode("utf-8", errors="replace").strip()
    if len(text) < MIN_TOKEN_CHARS or len(raw) > 4096:
        raise TokenFileError(
            f"the token must be {MIN_TOKEN_CHARS} to 4096 characters (try: openssl rand -hex 32)"
        )
    if not set(text) <= _TOKEN_CHARS:
        raise TokenFileError("the token may hold only visible ASCII characters, no spaces")
    return text.encode("ascii")


def parse_bind(text: str, *, allow_remote: bool) -> tuple[str, int]:
    """`HOST:PORT` (`[::1]:8765` for IPv6). A host that is not loopback needs `allow_remote`."""
    host, separator, port_text = text.rpartition(":")
    host = host.strip("[]")
    if not separator or not host or not port_text.isdigit() or int(port_text) > 65535:
        raise BindError("--http must be HOST:PORT, e.g. 127.0.0.1:8765")
    if not is_loopback_host(host) and not allow_remote:
        raise BindError(
            f"{host!r} is not a loopback address; the proxy is bound to loopback unless you give "
            "--allow-remote-bind (then anything that can reach the port can try the token)"
        )
    return host, int(port_text)


@dataclass(frozen=True)
class HttpSettings:
    token: bytes = field(repr=False)
    host: str = "127.0.0.1"
    port: int = 8765
    allowed_origins: frozenset[str] = frozenset()
    """Exact `Origin` values that are accepted (e.g. `http://localhost:3000`). A request with no
    `Origin` header (a command-line or desktop client) is always fine."""
    allow_remote: bool = False


class _Waiter:
    """A POST that waits for the answer to its request."""

    def __init__(self, request_id: JsonValue, *, streaming: bool) -> None:
        self.request_id = request_id
        self.streaming = streaming
        """Whether the reply is an SSE stream (the proxy's own requests may travel on it)."""
        self.events: queue.Queue[JsonObject | None] = queue.Queue()
        """Messages for the client in order, ending with the answer; None when the proxy ends."""


def _key(request_id: JsonValue) -> str:
    return json.dumps(request_id, sort_keys=True)


def _is_answer(message: JsonObject) -> bool:
    return (
        "method" not in message and "id" in message and ("result" in message or "error" in message)
    )


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, host: str, port: int, handler: type[BaseHTTPRequestHandler]) -> None:
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        super().__init__((host, port), handler)

    @override
    def server_bind(self) -> None:
        # `HTTPServer.server_bind` looks the host name up (`getfqdn`); a bind needs no lookup.
        TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


class AgentEndpoint:
    """The listening socket and the bridge to a `Dispatcher`. Create it, then call `serve`."""

    def __init__(
        self, settings: HttpSettings, *, keepalive_seconds: float = KEEPALIVE_SECONDS
    ) -> None:
        if not settings.allow_remote and not is_loopback_host(settings.host):
            raise BindError("the host is not loopback and allow_remote is not set")
        if len(settings.token) < MIN_TOKEN_CHARS:
            raise ValueError("the token is too short")
        self._settings = settings
        self._keepalive = keepalive_seconds
        self._lock = threading.Lock()
        self._waiters: dict[str, _Waiter] = {}
        self._stream: queue.Queue[JsonObject | None] | None = None
        self._session: str | None = None
        self._ended = False
        self._target: ProxyServer | None = None
        self._stop_requested = threading.Event()
        self._input_closed = threading.Event()
        input_read, input_write = os.pipe()
        output_read, output_write = os.pipe()
        self._input_read: IO[bytes] = os.fdopen(input_read, "rb")
        self._input_write: IO[bytes] = os.fdopen(input_write, "wb")
        self._output_read: IO[bytes] = os.fdopen(output_read, "rb")
        self._output_write: IO[bytes] = os.fdopen(output_write, "wb")
        self._write_lock = threading.Lock()
        handler = _handler_for(self)
        try:
            self._httpd = _Server(settings.host, settings.port, handler)
        except BaseException:
            self._close_pipes()
            raise
        self._loopback = is_loopback_host(settings.host)

    # -- public ----------------------------------------------------------------------------------

    @property
    def address(self) -> tuple[str, int]:
        """The host and port actually bound (the port is chosen when the settings say 0)."""
        host, port = self._httpd.server_address[:2]
        return str(host), int(port)

    @property
    def url(self) -> str:
        host, port = self.address
        shown = f"[{host}]" if ":" in host else host
        return f"http://{shown}:{port}{ENDPOINT}"

    def serve(self, server: ProxyServer, *, on_ready: Callable[[], None] | None = None) -> None:
        """Serve until the session is deleted or `stop()`; returns once the worker is idle.

        The calling thread runs the dispatcher's loop. Afterwards nothing touches the Gateway
        any more, so the caller may append `run_finished`.
        """
        self._target = server
        dispatcher = Dispatcher(server, self._input_read, self._output_write)
        threads = [
            threading.Thread(
                target=self._httpd.serve_forever,
                kwargs={"poll_interval": 0.05},
                name="notary-http",
                daemon=True,
            ),
            threading.Thread(target=self._route_output, name="notary-http-out", daemon=True),
            threading.Thread(target=self._watch_stop, name="notary-http-stop", daemon=True),
        ]
        for thread in threads:
            thread.start()
        if on_ready is not None:
            on_ready()
        try:
            dispatcher.run()
        finally:
            self._finish(threads)

    def stop(self) -> None:
        """End the run as a closed stdin does. Safe from a signal handler and from any thread."""
        self._stop_requested.set()

    def close(self) -> None:
        """Release the socket and the pipes when `serve` was never called."""
        self._httpd.server_close()
        self._close_pipes()

    # -- the dispatcher side ---------------------------------------------------------------------

    def _watch_stop(self) -> None:
        self._stop_requested.wait()
        self._close_input()

    def _close_input(self) -> None:
        """No more input: the dispatcher sees the end of its stream."""
        with self._write_lock:
            if self._input_closed.is_set():
                return
            self._input_closed.set()
            self._input_write.close()

    def _finish(self, threads: list[threading.Thread]) -> None:
        self._close_input()
        self._stop_requested.set()
        with self._lock:
            self._ended = True  # no new request is accepted
        # The worker has finished: its last answers are on the pipe; let the router deliver them
        # to the replies that wait for them BEFORE the rest of the replies are ended.
        self._output_write.close()
        threads[1].join()
        with self._lock:
            waiters = list(self._waiters.values())
            self._waiters.clear()
            stream, self._stream = self._stream, None
        for waiter in waiters:
            waiter.events.put(None)
        if stream is not None:
            stream.put(None)
        self._httpd.shutdown()
        self._httpd.server_close()
        self._input_read.close()
        self._output_read.close()

    def _close_pipes(self) -> None:
        for pipe in (self._input_read, self._input_write, self._output_read, self._output_write):
            pipe.close()

    def _route_output(self) -> None:
        """Hand each message the dispatcher wrote to the HTTP reply that waits for it."""
        while True:
            try:
                message = read_message(self._output_read)
            except MessageError:
                continue
            except (OSError, ValueError):
                return
            if message is None:
                return
            self._deliver(message)

    def _deliver(self, message: JsonObject) -> None:
        with self._lock:
            if _is_answer(message):
                waiter = self._waiters.pop(_key(message.get("id")), None)
                if waiter is not None:
                    waiter.events.put(message)
                return
            # A request or notification of the proxy for the client: the standalone stream if it
            # is open, else the stream of the oldest streaming request in flight (the call that
            # is running now, as calls run in arrival order).
            stream = self._stream
            if stream is None:
                for waiter in self._waiters.values():
                    if waiter.streaming:
                        stream = waiter.events
                        break
            if stream is None:
                diagnostic("a message for the client was dropped: no stream is open")
                return
            stream.put(message)

    def send(self, message: JsonObject) -> bool:
        """One line on the dispatcher's input; False once the input is closed."""
        line = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        with self._write_lock:
            if self._input_closed.is_set():
                return False
            try:
                self._input_write.write(line + b"\n")
                self._input_write.flush()
            except (OSError, ValueError):
                return False
            return True

    # -- the HTTP side (called on the connection threads) ----------------------------------------

    def _allowed_hosts(self) -> frozenset[str]:
        _, port = self.address
        names = {"localhost", "127.0.0.1", "[::1]", self._settings.host.strip("[]")}
        return frozenset(f"{name}:{port}" for name in names) | frozenset(
            f"[{name}]:{port}" for name in names if ":" in name
        )

    def gate(self, host: str | None, origin: str | None, authorization: str | None) -> int:
        """0 when the request may go on, else the HTTP status that refuses it."""
        if self._loopback and (host is None or host.lower() not in self._allowed_hosts()):
            return 403
        if origin is not None and origin not in self._settings.allowed_origins:
            return 403
        scheme, _, presented = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not presented:
            return 401
        # Constant time in the content (only a wrong length is noticed sooner).
        if not hmac.compare_digest(presented.strip().encode("utf-8"), self._settings.token):
            return 401
        return 0

    def open_session(self) -> str | None:
        """A new session id, None when the run already has its one session."""
        with self._lock:
            if self._session is not None or self._ended:
                return None
            self._session = secrets.token_hex(16)
            return self._session

    def session_state(self, presented: str | None) -> int:
        """0 for the session of this run, 400 without a header, 404 for any other id."""
        if presented is None:
            return 400
        with self._lock:
            current = self._session
        if current is None or not hmac.compare_digest(presented.encode(), current.encode()):
            return 404
        return 0

    def queued(self, method: str) -> bool:
        target = self._target
        return target is not None and target.queued(method)

    def begin(self, request_id: JsonValue, *, streaming: bool) -> _Waiter | None:
        """Register the reply for a request; None when the id is in flight or the run ended."""
        waiter = _Waiter(request_id, streaming=streaming)
        key = _key(request_id)
        with self._lock:
            if self._ended or key in self._waiters:
                return None
            self._waiters[key] = waiter
        return waiter

    def forget(self, request_id: JsonValue) -> None:
        with self._lock:
            self._waiters.pop(_key(request_id), None)

    def cancel(self, params: JsonObject) -> None:
        """The client cancelled a request: tell the dispatcher, and end that request's reply."""
        request_id = params.get("requestId")
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
            return
        with self._lock:
            waiter = self._waiters.pop(_key(request_id), None)
        if waiter is not None:
            waiter.events.put(error(request_id, REQUEST_CANCELLED, "request cancelled"))

    def attach_stream(self) -> queue.Queue[JsonObject | None] | None:
        with self._lock:
            if self._stream is not None or self._ended:
                return None
            self._stream = queue.Queue()
            return self._stream

    def detach_stream(self, stream: queue.Queue[JsonObject | None]) -> None:
        with self._lock:
            if self._stream is stream:
                self._stream = None

    @property
    def keepalive_seconds(self) -> float:
        return self._keepalive

    def end_session(self) -> None:
        """`DELETE`: the client is done; the run ends like a closed stdin."""
        self.stop()


def _handler_for(endpoint: AgentEndpoint) -> type["_Handler"]:
    class Bound(_Handler):
        pass

    Bound.endpoint = endpoint
    return Bound


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = CONNECTION_TIMEOUT
    endpoint: ClassVar[AgentEndpoint]

    @override
    def log_message(self, format: str, *args: object) -> None:
        return  # the default line holds the client address and the request line; we log refusals

    # -- replies ---------------------------------------------------------------------------------

    def _reply(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _refuse(self, status: int, code: int, message: str) -> None:
        """A fixed JSON-RPC error body; the connection closes (the body may be unread)."""
        self.close_connection = True
        headers = {"WWW-Authenticate": 'Bearer realm="notary"'} if status == 401 else {}
        body = json.dumps(error(None, code, message)).encode("utf-8")
        diagnostic(f"http: refused a request: {status} {message}")
        self._reply(status, body, headers)

    def _json(self, message: JsonObject, headers: dict[str, str] | None = None) -> None:
        self._reply(200, json.dumps(message, ensure_ascii=False).encode("utf-8"), headers)

    def _event(self, message: JsonObject) -> None:
        data = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        self.wfile.write(f"event: message\ndata: {data}\n\n".encode())
        self.wfile.flush()

    def _begin_stream(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True

    # -- checks ----------------------------------------------------------------------------------

    def _checked(self) -> bool:
        """The path, Host, Origin and token. False after the refusal has been sent."""
        if self.path.split("?", 1)[0] != ENDPOINT:
            self._refuse(404, INVALID_REQUEST, "not found")
            return False
        refused = self.endpoint.gate(
            self.headers.get("Host"), self.headers.get("Origin"), self.headers.get("Authorization")
        )
        if refused == 403:
            self._refuse(403, INVALID_REQUEST, "forbidden")
            return False
        if refused == 401:
            self._refuse(401, INVALID_REQUEST, "unauthorized")
            return False
        version = self.headers.get(VERSION_HEADER)
        if version is not None and version not in SUPPORTED_VERSIONS:
            self._refuse(400, INVALID_REQUEST, "unsupported MCP-Protocol-Version")
            return False
        return True

    def _in_session(self) -> bool:
        state = self.endpoint.session_state(self.headers.get(SESSION_HEADER))
        if state == 400:
            self._refuse(400, INVALID_REQUEST, f"{SESSION_HEADER} header is required")
        elif state == 404:
            self._refuse(404, INVALID_REQUEST, "no such session")
        return state == 0

    def _body(self) -> JsonObject | None:
        """The JSON object in the body, or None after a refusal was sent."""
        kind = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if kind != "application/json":
            self._refuse(415, INVALID_REQUEST, "Content-Type must be application/json")
            return None
        length = self.headers.get("Content-Length", "")
        if not length.isdigit():
            self._refuse(411, INVALID_REQUEST, "Content-Length is required")
            return None
        if int(length) > MAX_BODY_BYTES:
            self._refuse(413, INVALID_REQUEST, "the request is too large")
            return None
        raw = self.rfile.read(int(length))
        try:
            parsed: JsonValue = json.loads(raw)
        except ValueError:
            self._refuse(400, PARSE_ERROR, "parse error")
            return None
        message = as_object(parsed)
        if message is None:
            self._refuse(400, INVALID_REQUEST, "the body must be one JSON-RPC message")
            return None
        return message

    # -- verbs -----------------------------------------------------------------------------------

    def do_POST(self) -> None:
        if not self._checked():
            return
        message = self._body()
        if message is None:
            return
        method = as_str(message.get("method"))
        request_id = message.get("id")
        is_request = method is not None and "id" in message
        if is_request and (isinstance(request_id, bool) or not isinstance(request_id, (str, int))):
            self._refuse(400, INVALID_REQUEST, "the request id must be a string or an integer")
            return
        accept = (self.headers.get("Accept") or "").lower()
        wants_sse = "text/event-stream" in accept
        if is_request and not (wants_sse or "application/json" in accept or "*/*" in accept):
            self._refuse(406, INVALID_REQUEST, "Accept must allow application/json")
            return
        headers: dict[str, str] = {}
        if method == "initialize" and is_request:
            session = self.endpoint.open_session()
            if session is None:
                self._refuse(409, INVALID_REQUEST, "this proxy run already has its session")
                return
            headers[SESSION_HEADER] = session
        elif not self._in_session():
            return
        if not is_request:
            self._notify(message, method)
            return
        streaming = wants_sse and method is not None and self.endpoint.queued(method)
        waiter = self.endpoint.begin(request_id, streaming=streaming)
        if waiter is None:
            self._refuse(400, INVALID_REQUEST, "the request id is in flight, or the run has ended")
            return
        if not self.endpoint.send(message):
            self.endpoint.forget(request_id)
            self._refuse(503, INVALID_REQUEST, "the proxy is shutting down")
            return
        self._answer(waiter, headers)

    def _notify(self, message: JsonObject, method: str | None) -> None:
        if method == CANCELLED:
            self.endpoint.cancel(as_object(message.get("params")) or {})
        if self.endpoint.send(message):
            self._reply(202)
        else:
            self._refuse(503, INVALID_REQUEST, "the proxy is shutting down")

    def _answer(self, waiter: _Waiter, headers: dict[str, str]) -> None:
        if not waiter.streaming:
            final = waiter.events.get()
            if final is None:
                self._refuse(503, INVALID_REQUEST, "the proxy is shutting down")
            else:
                self._json(final, headers)
            return
        self._begin_stream()
        try:
            while True:
                item = waiter.events.get()
                if item is None:
                    return  # the proxy ended without an answer; the stream just ends
                self._event(item)
                if _is_answer(item) and item.get("id") == waiter.request_id:
                    return
        except (OSError, ValueError):
            self.endpoint.forget(waiter.request_id)  # the client went away; its call goes on

    def do_GET(self) -> None:
        if not self._checked() or not self._in_session():
            return
        if "text/event-stream" not in (self.headers.get("Accept") or "").lower():
            self._refuse(406, INVALID_REQUEST, "Accept must allow text/event-stream")
            return
        stream = self.endpoint.attach_stream()
        if stream is None:
            self._refuse(409, INVALID_REQUEST, "a stream is already open")
            return
        self._begin_stream()
        try:
            while True:
                try:
                    item = stream.get(timeout=self.endpoint.keepalive_seconds)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                if item is None:
                    return
                self._event(item)
        except (OSError, ValueError, http.client.HTTPException):
            return
        finally:
            self.endpoint.detach_stream(stream)

    def do_DELETE(self) -> None:
        if not self._checked() or not self._in_session():
            return
        self._reply(200)
        self.endpoint.end_session()
