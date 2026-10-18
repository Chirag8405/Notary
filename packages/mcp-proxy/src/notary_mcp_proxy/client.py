"""A minimal MCP client for one server run as a child process (stdio transport).

Requests are sent one at a time and answered in order; the server's own requests (sampling,
roots) are refused and its notifications ignored. There is no timeout: a server that never
answers blocks the proxy.
"""

import subprocess
from collections.abc import Sequence
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


class ServerError(Exception):
    """The server answered with an error, broke the protocol or exited."""


class StdioClient:
    def __init__(self, command: Sequence[str], *, cwd: Path | None = None) -> None:
        if not command:
            raise ValueError("empty server command")
        self._process = subprocess.Popen(
            list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=cwd
        )
        stdin, stdout = self._process.stdin, self._process.stdout
        if stdin is None or stdout is None:
            raise ServerError("server pipes are missing")
        self._stdin = stdin
        self._stdout = stdout
        self._next_id = 0

    def initialize(self) -> JsonObject:
        """The handshake; returns the server's `initialize` result."""
        answer = self.request(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO},
        )
        write_message(self._stdin, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        return answer

    def list_tools(self) -> list[JsonObject]:
        """Every tool the server reports now, following pagination."""
        tools: list[JsonObject] = []
        cursor: str | None = None
        while True:
            answer = self.request("tools/list", {} if cursor is None else {"cursor": cursor})
            for tool in as_list(answer.get("tools")) or []:
                entry = as_object(tool)
                if entry is None:
                    raise ServerError("tools/list returned a non-object tool")
                tools.append(entry)
            cursor = as_str(answer.get("nextCursor"))
            if cursor is None:
                return tools

    def call_tool(self, name: str, arguments: JsonObject) -> JsonObject:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def request(self, method: str, params: JsonObject) -> JsonObject:
        self._next_id += 1
        request_id = self._next_id
        try:
            write_message(
                self._stdin,
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            )
        except OSError as failure:
            raise ServerError(f"server stopped reading: {failure}") from failure
        while True:
            try:
                message = read_message(self._stdout)
            except MessageError as failure:
                raise ServerError(str(failure)) from failure
            if message is None:
                raise ServerError("server exited")
            if "method" in message:
                self._refuse(message)
                continue
            if message.get("id") != request_id:
                continue
            failure = as_object(message.get("error"))
            if failure is not None:
                raise ServerError(as_str(failure.get("message")) or "server error")
            answer = as_object(message.get("result"))
            if answer is None:
                raise ServerError(f"{method}: result is not an object")
            return answer

    def _refuse(self, message: JsonObject) -> None:
        """Answer a request from the server with "method not found"; ignore a notification."""
        request_id: JsonValue | None = message.get("id")
        if request_id is not None:
            write_message(self._stdin, error(request_id, METHOD_NOT_FOUND, "not supported"))

    def close(self) -> None:
        self._stdin.close()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
