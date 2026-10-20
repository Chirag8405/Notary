"""A minimal MCP client for a server reached over Streamable HTTP (spec 2025-06-18), stdlib only.

One endpoint URL. Every JSON-RPC message is a POST; the server answers a request with one JSON
body or an SSE stream (`text/event-stream`) that carries the answer, preceded by any number of
notifications. `initialize` may return `Mcp-Session-Id`, sent on every later request together with
`MCP-Protocol-Version`; `close` ends the session with a DELETE.

It behaves like `StdioClient` for everything above it (`McpClient`):

- one request at a time, with `timeout_seconds` for the WHOLE request (connect, headers and every
  line of a stream); on a timeout `notifications/cancelled` is POSTed and `ServerTimeoutError`
  raised. Each POST has its own response, so an answer cannot arrive late for another request;
- the server's own requests inside a stream (sampling, roots) are refused with -32601, its
  notifications go to `on_notification`, which here runs on the thread that called `request` (the
  Gateway's worker) and must not call `request`;
- the errors are the same constant `ServerError` messages: a connection that cannot be made or a
  session the server forgot (404) is `ServerExitedError`, a status that is not 2xx is
  `ServerRejectedError` (the status is in `detail`, for stderr only), a body that is not what the
  protocol says is a `ServerError`. Nothing the server wrote reaches the agent.

A forgotten session (404 for a request that carried `Mcp-Session-Id`) turns `alive` False for good,
as an exited process does for stdio: starting a new session would re-pin and could accept a rug
pull. A refused connection leaves `alive` True (the next call tries again; the manifest hash is
checked on every call anyway).

No standalone GET stream is opened: `tools/list_changed` is only seen when a stream carries it, and
a changed tool is caught by the per-call pre-flight listing in any case. Redirects are never
followed (the headers, which may hold a token, must not go to another host). The configured
headers are never logged.
"""

import contextlib
import http.client
import json
import re
import ssl
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from urllib.parse import urlsplit

from pydantic import JsonValue

from notary_mcp_proxy.client import (
    CLIENT_INFO,
    DEFAULT_TIMEOUT_SECONDS,
    PROTOCOL_VERSION,
    SUPPORTED_VERSIONS,
    Clock,
    McpClient,
    Notify,
    ServerError,
    ServerExitedError,
    ServerRejectedError,
    ServerTimeoutError,
    diagnostic,
    quoted,
)
from notary_mcp_proxy.jsonrpc import (
    METHOD_NOT_FOUND,
    JsonObject,
    as_object,
    as_str,
    error,
)

CANCEL_TIMEOUT_SECONDS = 2.0
"""How long the best-effort `notifications/cancelled` and the closing DELETE may take."""
MAX_MESSAGE_BYTES = 16 * 1024 * 1024
"""Largest JSON body, or SSE event, accepted from a server."""
SESSION_HEADER = "Mcp-Session-Id"
VERSION_HEADER = "MCP-Protocol-Version"
_SESSION_ID = re.compile(r"[\x21-\x7e]{1,256}")
"""A session id is visible ASCII (spec); anything else is refused, so it cannot inject a header."""
_JSON = "application/json"
_SSE = "text/event-stream"


class HttpClient(McpClient):
    def __init__(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        on_notification: Notify | None = None,
        clock: Clock = time.monotonic,
        cancel_timeout_seconds: float = CANCEL_TIMEOUT_SECONDS,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("the server URL must be http(s)://host[:port]/path")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds
        self.on_notification = on_notification
        self._clock = clock
        self._cancel_timeout = cancel_timeout_seconds
        self._secure = parts.scheme == "https"
        self._host = parts.hostname
        self._port = parts.port or (443 if self._secure else 80)
        self._target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        self._headers = dict(headers or {})
        self._tls = ssl.create_default_context() if self._secure else None
        self._session_id: str | None = None
        self._version: str | None = None
        self._next_id = 0
        self._request_lock = threading.Lock()
        self._closed = threading.Event()
        self._expired = threading.Event()

    @property
    def alive(self) -> bool:
        return not (self._closed.is_set() or self._expired.is_set())

    @property
    def session_id(self) -> str | None:
        return self._session_id

    def initialize(self) -> JsonObject:
        """The handshake; keeps the session id and the protocol version the server chose."""
        answer = self.request(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO},
        )
        version = as_str(answer.get("protocolVersion"))
        if version not in SUPPORTED_VERSIONS:
            raise ServerError(
                "the server broke the protocol",
                detail=f"initialize: unsupported protocolVersion {quoted(str(version))}",
            )
        self._version = version
        self._notify({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return answer

    def request(self, method: str, params: JsonObject) -> JsonObject:
        """One request, one answer; raises ServerError (or its timeout / exited subclasses)."""
        with self._request_lock:
            if not self.alive:
                raise ServerExitedError(detail=f"{method}: the session had already ended")
            self._next_id += 1
            request_id = self._next_id
            deadline = self._clock() + self.timeout_seconds
            message: JsonObject = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            }
            try:
                return self._exchange(method, request_id, message, deadline)
            except ServerTimeoutError:
                self._cancel(request_id)
                raise

    # -- one POST --------------------------------------------------------------------------------

    def _exchange(
        self, method: str, request_id: int, message: JsonObject, deadline: float
    ) -> JsonObject:
        connection = self._connect(self._remaining(method, deadline))
        try:
            try:
                connection.request("POST", self._target, self._body(message), self._send_headers())
                self._arm(connection, method, deadline)
                response = connection.getresponse()
            except TimeoutError:
                raise ServerTimeoutError(detail=f"{method}: no answer") from None
            except (OSError, http.client.HTTPException) as failure:
                raise ServerExitedError(
                    detail=f"{method}: connection failed: {type(failure).__name__}"
                ) from failure
            try:
                self._check_status(method, response)
                if method == "initialize":
                    self._keep_session(response)
                return self._read_answer(method, request_id, response, connection, deadline)
            finally:
                response.close()
        finally:
            connection.close()

    def _check_status(self, method: str, response: http.client.HTTPResponse) -> None:
        status = response.status
        if 200 <= status < 300 and status != 202:
            return
        if status == 404 and self._session_id is not None:
            self._expired.set()
            diagnostic("the server forgot the session; its tools are unavailable from now on")
            raise ServerExitedError(detail=f"{method}: HTTP 404, the session ended")
        # What the server wrote is for stderr only, bounded and quoted.
        snippet = ""
        with contextlib.suppress(OSError, http.client.HTTPException):
            snippet = response.read(200).decode("utf-8", errors="replace")
        raise ServerRejectedError(detail=f"{method}: HTTP {status} {quoted(snippet)}")

    def _keep_session(self, response: http.client.HTTPResponse) -> None:
        session = response.getheader(SESSION_HEADER)
        if session is None:
            return
        if _SESSION_ID.fullmatch(session) is None:
            raise ServerError(
                "the server broke the protocol", detail="initialize: bad Mcp-Session-Id"
            )
        self._session_id = session

    def _read_answer(
        self,
        method: str,
        request_id: int,
        response: http.client.HTTPResponse,
        connection: http.client.HTTPConnection,
        deadline: float,
    ) -> JsonObject:
        kind = (response.getheader("Content-Type") or "").split(";")[0].strip().lower()
        if kind == _JSON:
            self._arm(connection, method, deadline)
            body = self._guard(method, lambda: response.read(MAX_MESSAGE_BYTES + 1))
            if len(body) > MAX_MESSAGE_BYTES:
                raise ServerError("the server broke the protocol", detail=f"{method}: too large")
            message = _parse(method, body)
            if self._is_answer(message, request_id):
                return self._answer(method, message)
            raise ServerError(
                "the server broke the protocol", detail=f"{method}: the body is not our answer"
            )
        if kind != _SSE:
            raise ServerError(
                "the server broke the protocol",
                detail=f"{method}: Content-Type {quoted(kind)}",
            )
        for data in self._events(method, response, connection, deadline):
            message = _parse(method, data.encode("utf-8"))
            if self._is_answer(message, request_id):
                return self._answer(method, message)
            self._route(message)
        raise ServerError(
            "the server broke the protocol", detail=f"{method}: the stream ended before the answer"
        )

    @staticmethod
    def _is_answer(message: JsonObject, request_id: int) -> bool:
        answered = message.get("id")
        return (
            "method" not in message
            and ("result" in message or "error" in message)
            and not isinstance(answered, bool)
            and answered == request_id
        )

    def _events(
        self,
        method: str,
        response: http.client.HTTPResponse,
        connection: http.client.HTTPConnection,
        deadline: float,
    ) -> Iterator[str]:
        """The `data` of each SSE event of the stream, in order (spec of `text/event-stream`)."""
        lines: list[str] = []
        total = 0
        while True:
            self._arm(connection, method, deadline)
            raw = self._guard(method, lambda: response.readline(MAX_MESSAGE_BYTES + 1))
            if not raw:
                return
            total += len(raw)
            if total > MAX_MESSAGE_BYTES:
                raise ServerError("the server broke the protocol", detail=f"{method}: too large")
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if line:
                field, _, value = line.partition(":")
                if field == "data":
                    lines.append(value[1:] if value.startswith(" ") else value)
                continue
            if lines:
                yield "\n".join(lines)
                lines = []
            total = 0

    def _route(self, message: JsonObject) -> None:
        """A message in a stream that is not the answer: a notification, or a request to refuse."""
        method = as_str(message.get("method"))
        if method is None:
            return  # a stray response
        request_id: JsonValue | None = message.get("id")
        if request_id is not None:
            self._post_quietly(error(request_id, METHOD_NOT_FOUND, "not supported"))
            return
        handler = self.on_notification
        if handler is None:
            return
        try:
            handler(method, as_object(message.get("params")) or {})
        # a failing notification handler must not kill the reader; it decides nothing
        except Exception as failure:
            diagnostic(f"notification handler failed: {type(failure).__name__}")

    # -- plumbing --------------------------------------------------------------------------------

    def _remaining(self, method: str, deadline: float) -> float:
        left = deadline - self._clock()
        if left <= 0:
            raise ServerTimeoutError(detail=f"{method}: no answer")
        return left

    def _arm(self, connection: http.client.HTTPConnection, method: str, deadline: float) -> None:
        """Bound the next read by what is left of the request's time."""
        left = self._remaining(method, deadline)
        if connection.sock is not None:
            connection.sock.settimeout(left)

    def _guard(self, method: str, read: Callable[[], bytes]) -> bytes:
        try:
            return read()
        except TimeoutError:
            raise ServerTimeoutError(detail=f"{method}: no answer") from None
        except (OSError, http.client.HTTPException) as failure:
            raise ServerError(
                "the server broke the protocol",
                detail=f"{method}: the stream broke: {type(failure).__name__}",
            ) from failure

    def _connect(self, timeout: float) -> http.client.HTTPConnection:
        if self._tls is not None:
            return http.client.HTTPSConnection(
                self._host, self._port, timeout=timeout, context=self._tls
            )
        return http.client.HTTPConnection(self._host, self._port, timeout=timeout)

    def _send_headers(self) -> dict[str, str]:
        headers = dict(self._headers)
        headers["Content-Type"] = _JSON
        headers["Accept"] = f"{_JSON}, {_SSE}"
        if self._session_id is not None:
            headers[SESSION_HEADER] = self._session_id
        if self._version is not None:
            headers[VERSION_HEADER] = self._version
        return headers

    @staticmethod
    def _body(message: JsonObject) -> bytes:
        return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _notify(self, message: JsonObject) -> None:
        """POST a notification (or a response); the server answers 202 and no body."""
        connection = self._connect(self.timeout_seconds)
        try:
            try:
                connection.request("POST", self._target, self._body(message), self._send_headers())
                response = connection.getresponse()
                response.read(0)
            except TimeoutError:
                raise ServerTimeoutError(detail="notification: no answer") from None
            except (OSError, http.client.HTTPException) as failure:
                raise ServerExitedError(
                    detail=f"notification: connection failed: {type(failure).__name__}"
                ) from failure
            if not 200 <= response.status < 300:
                raise ServerRejectedError(detail=f"notification: HTTP {response.status}")
        finally:
            connection.close()

    def _post_quietly(self, message: JsonObject) -> None:
        """Best effort and short: a refusal or a cancel must not cost more than the request did."""
        connection = self._connect(self._cancel_timeout)
        try:
            with contextlib.suppress(OSError, http.client.HTTPException):
                connection.request("POST", self._target, self._body(message), self._send_headers())
                connection.getresponse().close()
        finally:
            connection.close()

    def _cancel(self, request_id: int) -> None:
        self._post_quietly(
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": request_id, "reason": "timeout"},
            }
        )

    def close(self) -> None:
        """End the session (DELETE; a server may answer 405) and stop using the server."""
        if self._closed.is_set():
            return
        self._closed.set()
        if self._session_id is None or self._expired.is_set():
            return
        connection = self._connect(self._cancel_timeout)
        try:
            with contextlib.suppress(OSError, http.client.HTTPException):
                connection.request("DELETE", self._target, headers=self._send_headers())
                connection.getresponse().close()
        finally:
            connection.close()


def _parse(method: str, data: bytes) -> JsonObject:
    try:
        message = json.loads(data)
    except ValueError:
        message = None
    parsed = as_object(message)
    if parsed is None:
        raise ServerError("the server broke the protocol", detail=f"{method}: not a JSON object")
    return parsed
