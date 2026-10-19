"""Drive the proxy as a child process the way an agent does: send, read the answers, then close.

A proxy drops the calls still queued when its stdin closes, so a test must read every answer it
expects before `finish()`. Answers are matched by id, never by position (fast methods are answered
while a call runs).
"""

import json
import queue
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO

from notary_mcp_proxy.jsonrpc import JsonObject, as_object

WAIT_SECONDS = 30.0
"""Only a failing test waits this long."""


def proxy_command(config: Path, *extra: str) -> list[str]:
    return [sys.executable, "-m", "notary_mcp_proxy", "--config", str(config), *extra]


def request(request_id: int, method: str, params: JsonObject | None = None) -> JsonObject:
    message: JsonObject = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def tool_call(request_id: int, name: str, arguments: JsonObject) -> JsonObject:
    return request(request_id, "tools/call", {"name": name, "arguments": arguments})


class StdioSession:
    def __init__(self, command: Sequence[str], *, env: Mapping[str, str] | None = None) -> None:
        self._process = subprocess.Popen(
            list(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=None if env is None else dict(env),
        )
        stdin, stdout, stderr = self._process.stdin, self._process.stdout, self._process.stderr
        assert stdin is not None
        assert stdout is not None
        assert stderr is not None
        self._stdin = stdin
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._answers: dict[object, JsonObject] = {}
        self._err: list[str] = []
        self._threads = [
            threading.Thread(target=self._pump_out, args=(stdout,), daemon=True),
            threading.Thread(target=self._pump_err, args=(stderr,), daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _pump_out(self, stream: IO[bytes]) -> None:
        for raw in iter(stream.readline, b""):
            self._lines.put(raw.decode("utf-8"))
        self._lines.put(None)

    def _pump_err(self, stream: IO[bytes]) -> None:
        for raw in iter(stream.readline, b""):
            self._err.append(raw.decode("utf-8"))

    def send(self, message: JsonObject) -> None:
        self._stdin.write(json.dumps(message).encode("utf-8") + b"\n")
        self._stdin.flush()

    def answer(self, request_id: int) -> JsonObject:
        """The answer with this id (messages for other ids are kept for their own call)."""
        while request_id not in self._answers:
            line = self._lines.get(timeout=WAIT_SECONDS)
            assert line is not None, "the proxy closed stdout before answering"
            message = as_object(json.loads(line))
            assert message is not None
            self._answers[message.get("id")] = message
        return self._answers[request_id]

    def result(self, request_id: int) -> JsonObject:
        """The `result` object of the answer with this id."""
        found = as_object(self.answer(request_id).get("result"))
        assert found is not None
        return found

    def finish(self) -> str:
        """Close stdin, wait for the proxy to exit and return its stderr."""
        self._stdin.close()
        assert self._process.wait(timeout=WAIT_SECONDS) == 0
        for thread in self._threads:
            thread.join(timeout=WAIT_SECONDS)
        return "".join(self._err)
