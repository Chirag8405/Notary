"""A minimal MCP client for one server run as a child process (stdio transport).

A reader thread parses every line the server writes. Responses go on a queue and `request` waits
for the one with its id, so a server that never answers costs `timeout_seconds`, not the proxy.
On a timeout the client sends `notifications/cancelled`, and an answer that arrives later is
ignored (its id is no longer awaited). The server's own requests (sampling, roots) are refused;
its notifications go to `on_notification`, which runs on the reader thread and must not call
`request`. When the process exits `alive` turns False for good: there is no restart, because a
restart would re-pin and could accept a rug pull.

Exceptions carry a constant message; whatever the server wrote is in `detail`, which is for
stderr only and never reaches the agent.
"""

import contextlib
import json
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from pydantic import JsonValue

from notary_mcp_proxy.jsonrpc import (
    METHOD_NOT_FOUND,
    JsonObject,
    MessageError,
    as_list,
    as_object,
    as_str,
    error,
    read_message,
    write_message,
)

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO: JsonObject = {"name": "notary-mcp-proxy", "version": "0.0.0"}
DEFAULT_TIMEOUT_SECONDS = 30.0
CLOSE_GRACE_SECONDS = 5.0
DETAIL_LIMIT = 200
MAX_PAGES = 100

Notify = Callable[[str, JsonObject], None]
Clock = Callable[[], float]


def diagnostic(text: str) -> None:
    """One line on stderr; stdout is reserved for MCP messages."""
    print(f"notary-mcp-proxy: {text}", file=sys.stderr, flush=True)


def quoted(text: str) -> str:
    """Server-authored text made safe for a log line: one line, quoted, bounded."""
    return json.dumps(text[:DETAIL_LIMIT], ensure_ascii=True)


class ServerError(Exception):
    """The server broke the protocol or answered with an error. The message is constant."""

    def __init__(self, message: str, *, detail: str = "") -> None:
        super().__init__(message)
        self.detail = detail
        """What the server (or the OS) said; for stderr only."""


class ServerTimeoutError(ServerError):
    """No answer in time."""

    def __init__(self, *, detail: str = "") -> None:
        super().__init__("the server did not answer in time", detail=detail)


class ServerExitedError(ServerError):
    """The process is gone."""

    def __init__(self, *, detail: str = "") -> None:
        super().__init__("the server is not running", detail=detail)


class ServerRejectedError(ServerError):
    """The server answered a request with a JSON-RPC error."""

    def __init__(self, *, detail: str = "") -> None:
        super().__init__("the server answered with an error", detail=detail)


class StdioClient:
    def __init__(
        self,
        command: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        on_notification: Notify | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        if not command:
            raise ValueError("empty server command")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds
        """Per request; may be changed between requests."""
        self.on_notification = on_notification
        self._clock = clock
        self._process = subprocess.Popen(
            list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=cwd
        )
        stdin, stdout = self._process.stdin, self._process.stdout
        if stdin is None or stdout is None:
            raise ServerExitedError(detail="server pipes are missing")
        self._stdin = stdin
        self._stdout = stdout
        self._next_id = 0
        self._request_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._inbox: queue.Queue[JsonObject | None] = queue.Queue()
        self._exited = threading.Event()
        self._closing = False
        self._reader = threading.Thread(target=self._read_loop, name="mcp-reader", daemon=True)
        self._reader.start()

    @property
    def alive(self) -> bool:
        """False once the server's stdout closed (the process exited)."""
        return not self._exited.is_set()

    def initialize(self) -> JsonObject:
        """The handshake; returns the server's `initialize` result."""
        answer = self.request(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO},
        )
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return answer

    def list_tools(self) -> list[JsonObject]:
        """Every tool the server reports now, following pagination."""
        return self.list_paged("tools/list", "tools")

    def list_paged(self, method: str, key: str) -> list[JsonObject]:
        """Every entry of a paginated listing (`tools/list`, `resources/list`, `prompts/list`...).

        `key` is the result field that holds the page. A server that never stops paging is a
        protocol error after `MAX_PAGES`.
        """
        entries: list[JsonObject] = []
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            answer = self.request(method, {} if cursor is None else {"cursor": cursor})
            for item in as_list(answer.get(key)) or []:
                entry = as_object(item)
                if entry is None:
                    raise ServerError(
                        "the server broke the protocol", detail=f"{method}: non-object entry"
                    )
                entries.append(entry)
            cursor = as_str(answer.get("nextCursor"))
            if cursor is None:
                return entries
        raise ServerError("the server broke the protocol", detail=f"{method}: too many pages")

    def call_tool(self, name: str, arguments: JsonObject) -> JsonObject:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def request(self, method: str, params: JsonObject) -> JsonObject:
        """One request, one answer; raises ServerError (or its timeout / exited subclasses)."""
        with self._request_lock:
            if not self.alive:
                raise ServerExitedError(detail=f"{method}: the process had already exited")
            self._next_id += 1
            request_id = self._next_id
            try:
                self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            except OSError as failure:
                raise ServerExitedError(detail=f"{method}: write failed: {failure}") from failure
            deadline = self._clock() + self.timeout_seconds
            while True:
                try:
                    message = self._inbox.get(timeout=max(deadline - self._clock(), 0.0))
                except queue.Empty:
                    self._cancel(request_id)
                    raise ServerTimeoutError(detail=f"{method}: no answer") from None
                if message is None:
                    raise ServerExitedError(detail=f"{method}: the server exited before answering")
                answered = message.get("id")
                if isinstance(answered, bool) or answered != request_id:
                    continue  # a late answer to an earlier, timed-out request
                return self._answer(method, message)

    def _answer(self, method: str, message: JsonObject) -> JsonObject:
        failure = as_object(message.get("error"))
        if failure is not None:
            raise ServerRejectedError(
                detail=f"{method}: {quoted(as_str(failure.get('message')) or '')}"
            )
        answer = as_object(message.get("result"))
        if answer is None:
            raise ServerError(
                "the server broke the protocol", detail=f"{method}: result is not an object"
            )
        return answer

    def _cancel(self, request_id: int) -> None:
        # If the server is gone or not reading, the timeout is reported anyway.
        with contextlib.suppress(OSError):
            self._send(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": request_id, "reason": "timeout"},
                }
            )

    def _send(self, message: JsonObject) -> None:
        with self._write_lock:
            write_message(self._stdin, message)

    def _read_loop(self) -> None:
        while True:
            try:
                message = read_message(self._stdout)
            except MessageError:
                diagnostic("the server wrote a line that is not a JSON object; ignored")
                continue
            except (OSError, ValueError):
                message = None
            if message is None:
                break
            self._route(message)
        code = self._process.wait()
        self._exited.set()
        if not self._closing:
            diagnostic(f"server exited with code {code}")
        self._inbox.put(None)

    def _route(self, message: JsonObject) -> None:
        method = as_str(message.get("method"))
        if method is None:
            if "id" in message:
                self._inbox.put(message)
            return
        request_id: JsonValue | None = message.get("id")
        if request_id is not None:
            with contextlib.suppress(OSError):
                self._send(error(request_id, METHOD_NOT_FOUND, "not supported"))
            return
        handler = self.on_notification
        if handler is None:
            return
        try:
            handler(method, as_object(message.get("params")) or {})
        except Exception as failure:
            diagnostic(f"notification handler failed: {type(failure).__name__}")

    def close(self) -> None:
        self._closing = True
        with contextlib.suppress(OSError), self._write_lock:
            self._stdin.close()
        try:
            self._process.wait(timeout=CLOSE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
        self._reader.join(timeout=CLOSE_GRACE_SECONDS)
