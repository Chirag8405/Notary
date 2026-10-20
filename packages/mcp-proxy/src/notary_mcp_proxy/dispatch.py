"""The proxy's message loop: fast methods at once, tool calls one at a time in arrival order.

Threads:

- the reader thread parses stdin. It answers `initialize`, `ping`, `tools/list`, `prompts/list`,
  unknown methods and invalid messages itself, so a slow tool call (or, later, a call waiting for a
  human) never blocks them. It queues every `tools/call` and, when they are configured, every
  `resources/*` read or listing and `prompts/get` (they label into the Gateway), applies
  `notifications/cancelled` and hands responses to the proxy's own requests (`ask_client`) to the
  thread that waits for them.
- ONE worker thread owns the Gateway. It takes work from a FIFO queue: tool calls in the order they
  arrived (so the audit chain order is the arrival order), drift checks and the user's prompts
  (`submit_user_prompt`, called by the control socket's thread, which waits for the worker's answer
  for a bounded time). The Gateway is never touched from any other thread.

Cancellation: `notifications/cancelled` for a queued call removes it (nothing is proposed, no
events, no response). For the running call it sets a flag (`cancelled`) that long waits check; the
decision already logged stays in the chain and the call gets no response. A cancel for an unknown
or finished id is ignored.

End of input: the reader stops, the call in progress finishes (its decision stays in the chain) and
the queued calls are dropped without any event: nobody is left to receive their results, and a
queued effect must not run for a client that has gone. A script that sends requests and closes
stdin must wait for the answers first.

Writes to the output are serialized, one message per line. A failed write (the agent is gone) is
reported once on stderr and later writes are skipped; the loop ends when the input does.
"""

import contextlib
import json
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import IO, Literal, Protocol

from pydantic import JsonValue

from notary_mcp_proxy.client import diagnostic
from notary_mcp_proxy.jsonrpc import (
    PARSE_ERROR,
    JsonObject,
    MessageError,
    as_object,
    as_str,
    error,
    read_message,
    write_message,
)

CANCELLED = "notifications/cancelled"
PROMPT_WAIT = 3.0
"""Seconds the control thread waits for the worker to store a prompt. The worker may be busy (a
tool call, a card waiting for the user); then the prompt is withdrawn and refused, never applied
late: a prompt the hook was told failed must not appear in the run afterwards."""

Wait = Callable[[threading.Event, float], bool]
"""How `ask_client` waits for an answer; tests replace it to avoid real time."""


class Target(Protocol):
    """What the dispatcher needs from the proxy (`ProxyServer` implements it)."""

    def queued(self, method: str) -> bool:
        """Whether a request with this method goes to the worker (`handle_call`)."""
        ...

    def handle_fast(self, message: JsonObject) -> JsonObject | None: ...

    def handle_call(self, message: JsonObject) -> JsonObject | None: ...

    def check_drift_now(self) -> None: ...

    def route_drift_checks(self, schedule: Callable[[], None]) -> None: ...

    def route_cancellation(
        self, cancelled: Callable[[JsonValue], bool], input_closed: Callable[[], bool]
    ) -> None: ...

    def route_client_requests(self, ask: "ClientAsker") -> None: ...

    def route_user_prompts(self, submit: "PromptSubmitter") -> None: ...

    def add_user_prompt(self, text: str) -> str | None:
        """Store the user's prompt as a trusted value; the new value's id, None when refused."""
        ...


class PromptSubmitter(Protocol):
    """`Dispatcher.submit_user_prompt`: hand a prompt to the worker that owns the Gateway."""

    def __call__(
        self, text: str, *, timeout: float = PROMPT_WAIT, run_timeout: float | None = None
    ) -> str | None: ...


class ClientAsker(Protocol):
    """`Dispatcher.ask_client`: what the proxy needs to send a request to the client."""

    def __call__(
        self,
        method: str,
        params: JsonObject,
        *,
        timeout: float,
        token: "AskToken | None" = None,
    ) -> JsonObject: ...


class ClientRequestError(Exception):
    """A request the proxy sent to the client got no usable answer. The message is constant."""

    def __init__(self, message: str, *, detail: str = "") -> None:
        super().__init__(message)
        self.detail = detail
        """What the client said, for stderr only."""


class ClientTimeoutError(ClientRequestError):
    def __init__(self) -> None:
        super().__init__("the client did not answer in time")


class ClientClosedError(ClientRequestError):
    def __init__(self) -> None:
        super().__init__("the client closed the connection")


class ClientRejectedError(ClientRequestError):
    def __init__(self, *, detail: str = "") -> None:
        super().__init__("the client answered with an error", detail=detail)


class ClientWithdrawnError(ClientRequestError):
    def __init__(self) -> None:
        super().__init__("the request was withdrawn before the client answered")


@dataclass
class _Pending:
    done: threading.Event = field(default_factory=threading.Event)
    response: JsonObject | None = None
    closed: bool = False
    withdrawn: bool = False


class AskToken:
    """Lets another thread take back a request `ask_client` is waiting on.

    `withdraw()` wakes the waiting `ask_client`, which tells the client to cancel the request
    (`notifications/cancelled`, so its UI can drop the form) and raises `ClientWithdrawnError`.
    A withdrawal before the request is sent means it is never sent. A late answer is ignored.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._withdrawn = False
        self._pending: _Pending | None = None

    def withdraw(self) -> None:
        with self._lock:
            self._withdrawn = True
            pending = self._pending
        if pending is not None:
            pending.withdrawn = True
            pending.done.set()

    def attach(self, pending: _Pending) -> bool:
        """Register the request; False when it was withdrawn already."""
        with self._lock:
            if self._withdrawn:
                return False
            self._pending = pending
            return True


@dataclass(frozen=True)
class _Call:
    request_id: str
    message: JsonObject


@dataclass(frozen=True)
class _Drift:
    pass


@dataclass(eq=False)
class _Prompt:
    """A prompt on its way to the worker. `state` and `value_id` change under the state lock."""

    text: str
    done: threading.Event = field(default_factory=threading.Event)
    state: Literal["queued", "running", "abandoned", "done"] = "queued"
    value_id: str | None = None


Work = _Call | _Drift | _Prompt
Phase = Literal["running", "eof"]


def _key(request_id: JsonValue) -> str:
    """Ids compare by their JSON text, so `1`, `1.0`, `"1"` and `true` stay distinct."""
    return json.dumps(request_id, sort_keys=True)


def _default_wait(event: threading.Event, timeout: float) -> bool:
    return event.wait(timeout)


class Dispatcher:
    def __init__(
        self,
        server: Target,
        reader: IO[bytes],
        writer: IO[bytes],
        *,
        wait: Wait = _default_wait,
    ) -> None:
        self._server = server
        self._reader = reader
        self._writer = writer
        self._wait = wait
        self._write_lock = threading.Lock()
        self._write_failed = False
        self._state = threading.Condition()
        self._queue: deque[Work] = deque()
        self._phase: Phase = "running"
        self._running: str | None = None
        self._running_cancelled = False
        self._drift_queued = False
        self._pending: dict[str, _Pending] = {}
        self._next_request = 0
        self._worker: threading.Thread | None = None
        self.input_ended = threading.Event()
        """Set once the reader saw the end of input and dropped the queue."""
        server.route_drift_checks(self._queue_drift_check)
        server.route_cancellation(self.cancelled, self.input_ended.is_set)
        server.route_client_requests(self.ask_client)
        server.route_user_prompts(self.submit_user_prompt)

    # -- public ----------------------------------------------------------------------------------

    def run(self) -> None:
        """Serve until the input ends; returns once the worker is idle."""
        worker = threading.Thread(target=self._work, name="notary-worker", daemon=True)
        self._worker = worker
        worker.start()
        reader = threading.Thread(target=self._read_loop, name="notary-stdin", daemon=True)
        reader.start()
        reader.join()
        worker.join()

    def ask_client(
        self,
        method: str,
        params: JsonObject,
        *,
        timeout: float,
        token: AskToken | None = None,
    ) -> JsonObject:
        """Send a request to the client and block the CALLING thread for its answer.

        Raises `ClientTimeoutError` (and tells the client to cancel), `ClientClosedError` when the
        input ended, `ClientRejectedError` when the client answered with a JSON-RPC error and
        `ClientWithdrawnError` (and tells the client to cancel) when `token.withdraw()` was called
        first.
        """
        pending = _Pending()
        with self._state:
            if self._phase == "eof":
                raise ClientClosedError
            if token is not None and not token.attach(pending):
                raise ClientWithdrawnError
            self._next_request += 1
            request_id = f"n{self._next_request}"
            self._pending[request_id] = pending
        self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        answered = self._wait(pending.done, timeout)
        with self._state:
            self._pending.pop(request_id, None)
        if pending.withdrawn:
            self._cancel_request(request_id, "withdrawn")
            raise ClientWithdrawnError
        if not answered and not pending.done.is_set():
            self._cancel_request(request_id, "timeout")
            raise ClientTimeoutError
        if pending.closed or pending.response is None:
            raise ClientClosedError
        failure = as_object(pending.response.get("error"))
        if failure is not None:
            code = failure.get("code")
            raise ClientRejectedError(detail=f"{method}: code {code}")
        return as_object(pending.response.get("result")) or {}

    def submit_user_prompt(
        self, text: str, *, timeout: float = PROMPT_WAIT, run_timeout: float | None = None
    ) -> str | None:
        """Queue the user's prompt for the worker and block the CALLING thread for its answer.

        Returns the id of the stored value, or None when it was not stored: the input has ended,
        the worker did not get to it within `timeout` (it is then withdrawn, so it can never be
        stored later), or the Gateway refused it. Never called on the worker thread.

        Once the worker has started on the prompt it is waited for `run_timeout` seconds (default:
        `timeout`). Storing is one append, except for the first prompt of a run that compiles a
        contract, which takes up to the compile timeout first (`ProxyServer.submit_user_prompt`).
        """
        item = _Prompt(text)
        with self._state:
            if self._phase == "eof":
                return None
            self._queue.append(item)
            self._state.notify_all()
        self._wait(item.done, timeout)
        with self._state:
            if item.state == "queued":
                item.state = "abandoned"
                with contextlib.suppress(ValueError):
                    self._queue.remove(item)
                return None
            running = item.state == "running"
        if running:
            # The worker has started on it: wait for the end of it.
            self._wait(item.done, timeout if run_timeout is None else run_timeout)
        with self._state:
            return item.value_id if item.state == "done" else None

    def _cancel_request(self, request_id: str, reason: str) -> None:
        self._write(
            {
                "jsonrpc": "2.0",
                "method": CANCELLED,
                "params": {"requestId": request_id, "reason": reason},
            }
        )

    def cancelled(self, request_id: JsonValue) -> bool:
        """Whether the call running now with this id was cancelled by the agent."""
        with self._state:
            return self._running == _key(request_id) and self._running_cancelled

    # -- reader thread ---------------------------------------------------------------------------

    def _read_loop(self) -> None:
        try:
            while True:
                try:
                    message = read_message(self._reader)
                except MessageError as failure:
                    self._write(error(None, PARSE_ERROR, str(failure)))
                    continue
                except (OSError, ValueError):
                    return
                if message is None:
                    return
                self._route(message)
        finally:
            self._end_of_input()

    def _route(self, message: JsonObject) -> None:
        method = as_str(message.get("method"))
        if method is None:
            if "id" in message and ("result" in message or "error" in message):
                self._response(message)
                return
        elif "id" not in message:
            if method == CANCELLED:
                self._cancel(as_object(message.get("params")) or {})
            return
        elif self._server.queued(method):
            with self._state:
                self._queue.append(_Call(_key(message.get("id")), message))
                self._state.notify_all()
            return
        answer = self._server.handle_fast(message)
        if answer is not None:
            self._write(answer)

    def _response(self, message: JsonObject) -> None:
        request_id = message.get("id")
        if not isinstance(request_id, str):
            return
        with self._state:
            pending = self._pending.get(request_id)
        if pending is None:
            return  # not ours, or already timed out
        pending.response = message
        pending.done.set()

    def _cancel(self, params: JsonObject) -> None:
        request_id = params.get("requestId")
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
            return
        key = _key(request_id)
        with self._state:
            for item in self._queue:
                if isinstance(item, _Call) and item.request_id == key:
                    self._queue.remove(item)
                    return
            if self._running == key:
                self._running_cancelled = True

    def _end_of_input(self) -> None:
        with self._state:
            self._phase = "eof"
            dropped = [item for item in self._queue if isinstance(item, _Prompt)]
            self._queue.clear()
            waiting = list(self._pending.values())
            self._pending.clear()
            self._state.notify_all()
        for pending in waiting:
            pending.closed = True
            pending.done.set()
        for prompt in dropped:
            prompt.done.set()  # state stays "queued": its submitter answers "not stored"
        self.input_ended.set()

    def _queue_drift_check(self) -> None:
        """Called on the client's reader thread: queue one drift check (coalesced)."""
        with self._state:
            if self._drift_queued or self._phase == "eof":
                return
            self._drift_queued = True
            self._queue.append(_Drift())
            self._state.notify_all()

    # -- worker thread ---------------------------------------------------------------------------

    def _work(self) -> None:
        while True:
            with self._state:
                while not self._queue and self._phase != "eof":
                    self._state.wait()
                if self._phase == "eof":
                    return
                item = self._queue.popleft()
                if isinstance(item, _Call):
                    self._running = item.request_id
                    self._running_cancelled = False
                elif isinstance(item, _Drift):
                    self._drift_queued = False
                else:
                    item.state = "running"
            try:
                if isinstance(item, _Call):
                    self._run_call(item)
                elif isinstance(item, _Drift):
                    self._server.check_drift_now()
                else:
                    self._run_prompt(item)
            # keep the worker alive; handle_call turns its own errors into JSON-RPC errors
            except Exception as failure:
                diagnostic(f"worker failed: {type(failure).__name__}")

    def _run_prompt(self, item: _Prompt) -> None:
        value_id: str | None = None
        try:
            value_id = self._server.add_user_prompt(item.text)
        finally:
            with self._state:
                item.value_id = value_id
                item.state = "done"
            item.done.set()

    def _run_call(self, item: _Call) -> None:
        try:
            answer = self._server.handle_call(item.message)
        finally:
            with self._state:
                suppressed = self._running_cancelled
                self._running = None
                self._running_cancelled = False
        if answer is not None and not suppressed:
            self._write(answer)

    # -- output ----------------------------------------------------------------------------------

    def _write(self, message: JsonObject) -> None:
        with self._write_lock:
            if self._write_failed:
                return
            try:
                write_message(self._writer, message)
            except (OSError, ValueError) as failure:
                self._write_failed = True
                diagnostic(f"cannot write to the agent: {type(failure).__name__}")
