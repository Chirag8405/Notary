"""The MCP server an agent (e.g. Claude Code) connects to: every tool call goes through the Gateway.

Only the tools in the contract are listed, with the manifests pinned at startup. A call is
labeled, decided and logged by the Gateway; the agent gets the labeled result fields on ALLOW
and an error naming the failing checks otherwise. An ESCALATE is reported as not run: the proxy
has no approval channel yet.
"""

import queue
import re
import threading
from collections.abc import Callable, Sequence
from typing import IO

from pydantic import JsonValue

from notary_core.models import AuditEntry, Decision
from notary_core.pinning import PinReport
from notary_mcp_proxy.client import PROTOCOL_VERSION, ServerError, diagnostic, quoted
from notary_mcp_proxy.gateway import Gateway, MediationOutcome, RawCall
from notary_mcp_proxy.jsonrpc import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    JsonObject,
    MessageError,
    as_object,
    as_str,
    error,
    read_message,
    result,
    write_message,
)
from notary_mcp_proxy.mcp_backend import (
    RESULT_RECORD,
    PinnedTool,
    encode_argument,
    exposed_definition,
    report,
    unchecked_text,
)
from notary_mcp_proxy.structured import (
    PREFIX,
    TYPES_FIELD,
    StructureError,
    compact,
    leaves_from,
    unflatten,
)

SUPPORTED_VERSIONS = frozenset({"2024-11-05", "2025-03-26", PROTOCOL_VERSION})
SERVER_INFO: JsonObject = {"name": "notary", "version": "0.0.0"}
INSTRUCTIONS = (
    "Every tool call is checked by NOTARY against the user's frozen intent contract. "
    "A blocked call did not run; do not retry it with other arguments to get around the check."
)

AuditSink = Callable[[Sequence[AuditEntry]], None]

LIST_CHANGED = "notifications/tools/list_changed"

ERR_REBUILD = "the tool result could not be rebuilt from its logged fields"


def _text_result(text: str, *, is_error: bool) -> JsonObject:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _reasons(decision: Decision | None) -> str:
    if decision is None:
        return ""
    failing = [r for r in decision.reasons if r.outcome != "pass"]
    return "\n".join(f"- {r.check}: {r.code} ({r.detail})" for r in failing)


def _drift_line(pins: PinReport) -> str:
    def names(values: Sequence[str]) -> str:
        return "[" + ", ".join(quoted(value) for value in values) + "]"

    verdict = "no drift" if pins.ok else "DRIFT (calls to drifted tools stay blocked)"
    return (
        f"tools/list_changed: {verdict}; drifted={names(pins.drifted)} "
        f"unpinned={names(pins.unpinned)} missing={names(pins.missing)}"
    )


class _Labeled:
    """What a call's logged values say: the text blocks and the rebuilt structured content."""

    def __init__(self, blocks: list[str], structured: JsonObject | None) -> None:
        self.blocks = blocks
        self.structured = structured

    def texts(self) -> list[str]:
        """The structured content serialized (older clients read only text), then the blocks."""
        if self.structured is None:
            return list(self.blocks)
        return [compact(self.structured), *self.blocks]

    def result(self, *, is_error: bool, lead: str | None = None) -> JsonObject:
        texts = self.texts()
        if lead is not None:
            texts = [lead, *texts]
        content: list[JsonValue] = [{"type": "text", "text": text} for text in texts]
        answer: JsonObject = {"content": content, "isError": is_error}
        if self.structured is not None:
            answer["structuredContent"] = self.structured
        return answer


class ProxyServer:
    def __init__(
        self, gateway: Gateway, tools: Sequence[PinnedTool], *, audit: AuditSink | None = None
    ) -> None:
        self._gateway = gateway
        self._tools: list[JsonObject] = [exposed_definition(tool) for tool in tools]
        self._audit = audit
        self._logged = 0
        self._calls = 0
        self._drift_requests: queue.Queue[None] = queue.Queue()
        self._drift_worker: threading.Thread | None = None

    @property
    def gateway(self) -> Gateway:
        return self._gateway

    def handle(self, message: JsonObject) -> JsonObject | None:
        """The answer to one message; None for a notification or a stray response."""
        method = as_str(message.get("method"))
        if "id" not in message:
            return None
        request_id: JsonValue = message.get("id")
        if method is None:
            if "result" in message or "error" in message:
                return None
            return error(request_id, INVALID_REQUEST, "missing method")
        params = as_object(message.get("params")) or {}
        try:
            if method == "initialize":
                return result(request_id, self._initialize(params))
            if method == "ping":
                return result(request_id, {})
            if method == "tools/list":
                return result(request_id, {"tools": list(self._tools)})
            if method == "tools/call":
                name = as_str(params.get("name"))
                if name is None:
                    return error(request_id, INVALID_PARAMS, "missing tool name")
                arguments = as_object(params.get("arguments")) or {}
                return result(request_id, self._call(name, arguments))
            return error(request_id, METHOD_NOT_FOUND, f"method not found: {method}")
        except Exception as failure:
            # The exception text may quote server-authored data: it goes to stderr, not the agent.
            diagnostic(
                f"internal error in {method}: {type(failure).__name__}: {quoted(str(failure))}"
            )
            return error(request_id, INTERNAL_ERROR, "internal error")
        finally:
            self._flush_audit()

    def _initialize(self, params: JsonObject) -> JsonObject:
        asked = as_str(params.get("protocolVersion"))
        version = asked if asked in SUPPORTED_VERSIONS else PROTOCOL_VERSION
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
            "instructions": INSTRUCTIONS,
        }

    def _call(self, tool: str, arguments: JsonObject) -> JsonObject:
        self._calls += 1
        call = RawCall(
            call_id=f"c{self._calls}",
            tool=tool,
            args={name: encode_argument(value) for name, value in arguments.items()},
        )
        try:
            outcome = self._gateway.propose(call)
        except ServerError as failure:
            # The pre-flight listing failed: no decision was made and nothing ran.
            report(f"call {tool}", failure)
            return _text_result(f"{tool} failed: {unchecked_text(failure)}", is_error=True)
        return self._answer(call, outcome)

    def on_server_notification(self, method: str, params: JsonObject) -> None:
        """Called on the client's reader thread: a changed tool list triggers a drift check.

        The check itself runs on a worker (it needs `tools/list`, which the reader thread cannot
        wait for). Requests are coalesced, so a flood of notifications costs one check at a time.
        """
        if method != LIST_CHANGED:
            return
        if self._drift_worker is None:
            self._drift_worker = threading.Thread(
                target=self._drift_loop, name="drift-check", daemon=True
            )
            self._drift_worker.start()
        self._drift_requests.put(None)

    def wait_for_drift_checks(self) -> None:
        """Block until every requested drift check has finished (tests use this)."""
        self._drift_requests.join()

    def _drift_loop(self) -> None:
        while True:
            self._drift_requests.get()
            extra = 0
            while True:
                try:
                    self._drift_requests.get_nowait()
                except queue.Empty:
                    break
                extra += 1
            try:
                self._check_drift()
            finally:
                for _ in range(extra + 1):
                    self._drift_requests.task_done()

    def _check_drift(self) -> None:
        try:
            pins = self._gateway.check_drift()
        except ServerError as failure:
            report("tools/list_changed drift check", failure)
        except Exception as failure:
            diagnostic(f"drift check failed: {type(failure).__name__}")
        else:
            diagnostic(_drift_line(pins))

    def _answer(self, call: RawCall, outcome: MediationOutcome) -> JsonObject:
        if outcome.status == "executed":
            try:
                return self._labeled(call).result(is_error=False)
            except StructureError as failure:
                diagnostic(f"{call.tool}: {quoted(str(failure))}")
                return _text_result(f"NOTARY halted: {ERR_REBUILD}", is_error=True)
        if outcome.status == "blocked":
            text = f"NOTARY blocked {call.tool}; it did not run.\n{_reasons(outcome.decision)}"
        elif outcome.status == "escalated":
            text = (
                f"NOTARY escalated {call.tool} ({outcome.endorsement_id}): it needs the user's "
                f"endorsement and did not run.\n{_reasons(outcome.decision)}"
            )
        elif outcome.status == "tool_error":
            # outcome.error is one of our constants; the server's content follows as labeled text.
            try:
                labeled = self._labeled(call)
            except StructureError as failure:
                diagnostic(f"{call.tool}: {quoted(str(failure))}")
                return _text_result(f"{call.tool} failed: {outcome.error}", is_error=True)
            lead = f"{call.tool} failed: {outcome.error}"
            if labeled.structured is None:
                return _text_result("\n".join([lead, *labeled.blocks]).rstrip(), is_error=True)
            return labeled.result(is_error=True, lead=lead)
        else:
            text = f"NOTARY halted: {outcome.error}"
        return _text_result(text.rstrip(), is_error=True)

    def _labeled(self, call: RawCall) -> _Labeled:
        """The call's result, read back from the store it was labeled into.

        Every value of a record `<call_id>.result` or `<call_id>.result-N`. The text blocks are the
        `content_NNN` fields; `structuredContent` is rebuilt from the `structured.*` fields, so the
        agent gets exactly the values that were logged, with the readers they were logged under.
        """
        pattern = re.compile(rf"{re.escape(call.call_id)}\.{RESULT_RECORD}(?:-[0-9]+)?\.(.*)", re.S)
        blocks: dict[str, str] = {}
        leaves: dict[str, str] = {}
        kinds: str | None = None
        for value_id, value in self._gateway.store.as_mapping().items():
            found = pattern.fullmatch(value_id)
            if found is None:
                continue
            name = found.group(1)
            if name == TYPES_FIELD:
                kinds = value.text
            elif name == PREFIX or name.startswith(f"{PREFIX}."):
                leaves[name] = value.text
            else:
                blocks[name] = value.text
        texts = [blocks[name] for name in sorted(blocks)]
        if not leaves:
            return _Labeled(texts, None)
        rebuilt = as_object(unflatten(leaves_from(leaves, kinds)))
        if rebuilt is None:
            raise StructureError("structured content is not an object")
        return _Labeled(texts, rebuilt)

    def _flush_audit(self) -> None:
        chain = self._gateway.chain
        if self._audit is not None and len(chain) > self._logged:
            self._audit(chain[self._logged :])
        self._logged = len(chain)


def serve(server: ProxyServer, reader: IO[bytes], writer: IO[bytes]) -> None:
    """Answer messages until the agent closes the stream."""
    while True:
        try:
            message = read_message(reader)
        except MessageError as failure:
            write_message(writer, error(None, PARSE_ERROR, str(failure)))
            continue
        if message is None:
            return
        answer = server.handle(message)
        if answer is not None:
            write_message(writer, answer)
