"""The MCP server an agent (e.g. Claude Code) connects to: every tool call goes through the Gateway.

Only the tools in the contract are listed, with the manifests pinned at startup. A call is
labeled, decided and logged by the Gateway; the agent gets the labeled result fields on ALLOW
and an error naming the failing checks otherwise. An ESCALATE makes the call WAIT on the
`ApprovalDesk` while the user approves or rejects the card on the control socket (a channel the
agent does not reach through MCP); the agent then gets the result of the second decision (the
tool's result after an approval, an error after a rejection, a timeout, a cancel or no desk).
When the client declared MCP elicitation (and the config allows it) the same card is also put to
the user in the client's own UI; the first answer, from the client or from the socket, wins.
"""

import queue
import re
import threading
from collections.abc import Callable, Sequence
from typing import IO, Literal

from pydantic import JsonValue

from notary_core.contract import ContractWideningError
from notary_core.endorsement import ERR_BAD_APPROVAL_ROW, approval_entries, render_card
from notary_core.models import (
    Decision,
    DecisionMade,
    DecisionUnit,
    IntentContract,
    ResolvedValue,
    RunFinished,
    ValueLabeled,
)
from notary_core.pinning import PinReport
from notary_mcp_proxy.approvals import Answer, ApprovalDesk, Pending, printable
from notary_mcp_proxy.client import PROTOCOL_VERSION, ServerError, diagnostic, quoted
from notary_mcp_proxy.compile_client import COMPILE_TIMEOUT, PromptCompiler
from notary_mcp_proxy.content import (
    IGNORED_NOTIFICATIONS,
    QUEUED,
    ContentProxy,
)
from notary_mcp_proxy.dispatch import (
    PROMPT_WAIT,
    AskToken,
    ClientAsker,
    ClientRequestError,
    ClientTimeoutError,
    ClientWithdrawnError,
    Dispatcher,
    PromptSubmitter,
)
from notary_mcp_proxy.elicit import METHOD, approval_request, parse_answer, supports_form
from notary_mcp_proxy.gateway import Gateway, MediationOutcome, RawCall
from notary_mcp_proxy.jsonrpc import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    JsonObject,
    as_object,
    as_str,
    error,
    result,
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

LIST_CHANGED = "notifications/tools/list_changed"

COMPILING_PROMPT_WAIT = COMPILE_TIMEOUT + PROMPT_WAIT
"""Seconds the control thread waits for the FIRST prompt once the worker has started on it, when
that prompt compiles the contract: the compile (at most `COMPILE_TIMEOUT`) plus the appends. The
hook waits longer than the worst case of the two waits (`PROMPT_WAIT` + this), see
`prompt_hook.HOOK_TIMEOUT`."""

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


def _never(*_: JsonValue) -> bool:
    return False


class _Elicitation:
    """One `elicitation/create` for one open card, asked from a thread of its own.

    The worker thread waits on the desk (so the control socket keeps working); this thread waits
    for the client and only RECORDS the answer on the desk, which refuses it when the socket (or
    a timeout, cancel or the end of input) decided first. When the worker is done it calls
    `stop()`: a request still open is withdrawn, so the client drops the form, and a late answer is
    ignored.
    """

    def __init__(self, ask: ClientAsker, desk: ApprovalDesk, pending: Pending) -> None:
        self._ask = ask
        self._desk = desk
        self._pending = pending
        self._token = AskToken()
        self.failure: tuple[str, str] | None = None
        """(cause, why) when the request failed instead of being answered; set before `stop`."""
        self._thread = threading.Thread(target=self._run, name="notary-elicitation", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._token.withdraw()
        self._thread.join()

    def _run(self) -> None:
        endorsement_id = self._pending.endorsement_id
        try:
            answer = self._ask(
                METHOD,
                approval_request(self._pending),
                timeout=self._desk.timeout_seconds,
                token=self._token,
            )
        except ClientWithdrawnError:
            return
        except ClientRequestError as failure:
            diagnostic(f"{endorsement_id}: elicitation failed: {quoted(str(failure))}")
            if isinstance(failure, ClientTimeoutError):
                self.failure = ("timeout", f"no answer within {self._desk.timeout_seconds:g} s")
            else:
                self.failure = ("client error", "the client could not ask the user")
            if not self._desk.decide(endorsement_id, "reject"):
                self.failure = None
            return
        choice = parse_answer(answer)
        counted = self._desk.decide(endorsement_id, choice)
        action = as_str(answer.get("action"))
        diagnostic(
            f"{endorsement_id}: elicitation answered {quoted(action or '?')} -> {choice}"
            + ("" if counted else " (too late, ignored)")
        )


class ProxyServer:
    def __init__(
        self,
        gateway: Gateway,
        tools: Sequence[PinnedTool],
        desk: ApprovalDesk | None = None,
        *,
        control_hint: str = "",
        reject_unanswered: bool = False,
        elicitation: bool = True,
        content: ContentProxy | None = None,
        prompt_compiler: PromptCompiler | None = None,
    ) -> None:
        """`desk` is where an escalated call waits for the user.

        With `elicitation`, a client that declared the capability is also asked in its own UI
        (needs a desk; the dispatcher routes the client requests). `content` serves the resources
        and prompts the config switches on; without it they are hidden (method not found).
        With a `prompt_compiler` the Gateway's `run_started` is deferred (`Gateway.defer_start`)
        and the first prompt may replace the contract by a narrower one before it is written;
        the first thing that needs the chain instead (a tool call, a queued resource or prompt
        request, a drift check, the end of input) starts the run with the config's contract, and
        the run never compiles after that.

        Without a desk, `reject_unanswered` (`--control none`) rejects every escalation at once;
        otherwise the call is answered "escalated" and the endorsement stays pending for the
        embedder to resolve through the Gateway (in-process harnesses). `control_hint` is printed
        with each card (how the user answers it, e.g. the CLI line).
        """
        self._gateway = gateway
        self._content = content
        self._desk = desk
        self._control_hint = control_hint
        self._reject_unanswered = reject_unanswered
        self._elicitation = elicitation
        self._client_elicits = False
        self._ask: ClientAsker | None = None
        self._submit_prompt: PromptSubmitter | None = None
        self._compiler = prompt_compiler
        self._elicit_failures: dict[str, tuple[str, str]] = {}
        self._approved: list[str] = []
        self._rejected_ids: list[tuple[str, str]] = []
        self._cancelled: Callable[[JsonValue], bool] = _never
        self._input_closed: Callable[[], bool] = lambda: False
        self._tools: list[JsonObject] = [exposed_definition(tool) for tool in tools]
        self._calls = 0
        self._drift_requests: queue.Queue[None] = queue.Queue()
        self._drift_worker: threading.Thread | None = None
        self._schedule_drift: Callable[[], None] | None = None

    @property
    def gateway(self) -> Gateway:
        return self._gateway

    def handle(self, message: JsonObject) -> JsonObject | None:
        """The answer to one message, synchronously; None for a notification or a stray response.

        One thread does everything here (the in-process tests, scripts). The `Dispatcher` instead
        calls `handle_fast` on the reader thread and `handle_call` on its single worker thread.
        """
        if self.queued(as_str(message.get("method")) or ""):
            return self.handle_call(message)
        return self.handle_fast(message)

    def queued(self, method: str) -> bool:
        """`tools/call`, and the resource and prompt requests that touch the Gateway or a server
        (only when configured: hidden ones are answered at once with method-not-found)."""
        if method == "tools/call":
            return True
        return method in QUEUED and self._content is not None and self._content.serves(method)

    def handle_fast(self, message: JsonObject) -> JsonObject | None:
        """`initialize`, `ping`, `tools/list`, unknown methods and invalid messages.

        Safe on the reader thread while a call runs: it never touches the Gateway (`prompts/list`
        shows the pinned definitions). A queued method is not answered here (`handle_call` does).
        """
        if self.queued(as_str(message.get("method")) or ""):
            return error(message.get("id"), INTERNAL_ERROR, "this method is not a fast method")
        return self._respond(message)

    def handle_call(self, message: JsonObject) -> JsonObject | None:
        """A queued method: label, decide, run. Only the thread that owns the Gateway calls this."""
        self._begin_run()
        return self._respond(message)

    def _begin_run(self) -> None:
        """Start the run with the contract in force and close the window for compiling one.

        Idempotent. Called by whatever needs the chain before a prompt did: after it the contract
        is the config's and stays so (I5). On the Gateway's thread only.
        """
        self._compiler = None
        self._gateway.ensure_started()

    def finish_run(self) -> None:
        """Append `run_finished` once the agent has closed the connection.

        Call it on the thread that owns the Gateway, or after that thread has finished (the
        `Dispatcher` has joined its worker when `serve` returns). A halted gateway still tries (the
        append fails again when the log is what broke) and says so in the summary.
        """
        self._begin_run()
        halted = self._gateway.halted
        outcome: Literal["completed", "error"] = "completed" if halted is None else "error"
        summary = (
            f"closed by the agent after {self._calls} tool calls"
            if halted is None
            else f"halted: {halted}; closed after {self._calls} tool calls"
        ) + self._escalation_summary()
        self._gateway.emit(
            lambda run, lane, seq: RunFinished(
                type="run_finished",
                run_id=run,
                lane=lane,
                seq=seq,
                outcome=outcome,
                summary=summary,
            )
        )

    def _escalation_summary(self) -> str:
        """How the escalations ended, for `run_finished` (a rejection has no event of its own).

        `; approved: e2; rejected: e1 (user), e3 (timeout)`; empty when nothing escalated.
        """
        parts: list[str] = []
        if self._approved:
            parts.append("approved: " + ", ".join(self._approved))
        if self._rejected_ids:
            parts.append(
                "rejected: " + ", ".join(f"{eid} ({cause})" for eid, cause in self._rejected_ids)
            )
        return "".join(f"; {part}" for part in parts)

    def _respond(self, message: JsonObject) -> JsonObject | None:
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
            content = self._content
            if content is not None and content.serves(method):
                return content.handle(request_id, method, params)
            if method == "tools/call":
                name = as_str(params.get("name"))
                if name is None:
                    return error(request_id, INVALID_PARAMS, "missing tool name")
                arguments = as_object(params.get("arguments")) or {}
                return result(request_id, self._call(name, arguments, request_id))
            return error(request_id, METHOD_NOT_FOUND, f"method not found: {method}")
        except Exception as failure:
            # The exception text may quote server-authored data: it goes to stderr, not the agent.
            diagnostic(
                f"internal error in {method}: {type(failure).__name__}: {quoted(str(failure))}"
            )
            return error(request_id, INTERNAL_ERROR, "internal error")

    def _initialize(self, params: JsonObject) -> JsonObject:
        asked = as_str(params.get("protocolVersion"))
        version = asked if asked in SUPPORTED_VERSIONS else PROTOCOL_VERSION
        self._client_elicits = supports_form(params.get("capabilities"))
        return {
            "protocolVersion": version,
            "capabilities": {
                "tools": {"listChanged": False},
                **({} if self._content is None else self._content.capabilities()),
            },
            "serverInfo": SERVER_INFO,
            "instructions": INSTRUCTIONS,
        }

    def _call(self, tool: str, arguments: JsonObject, request_id: JsonValue) -> JsonObject:
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
        if outcome.status == "escalated" and (self._desk is not None or self._reject_unanswered):
            return self._after_escalation(call, outcome, request_id)
        return self._answer(call, outcome)

    def _after_escalation(
        self, call: RawCall, outcome: MediationOutcome, request_id: JsonValue
    ) -> JsonObject:
        """Wait for the user, then let the Gateway decide again (approve) or close it (reject).

        Runs on the worker thread, which owns the Gateway: a choice made on the control thread is
        only recorded on the desk and applied here. The worker is blocked meanwhile by design:
        fast methods are still answered and later calls queue behind this one.
        """
        endorsement_id = outcome.endorsement_id
        card = next(
            (
                p
                for p in self._gateway.pending_endorsements()
                if p.endorsement.endorsement_id == endorsement_id
            ),
            None,
        )
        desk = self._desk
        if endorsement_id is None or card is None or desk is None:
            return self._rejected(call, outcome, Answer("reject", "closed"), disabled=True)
        text = printable(render_card(card.endorsement.card))
        pending = Pending(
            endorsement_id=endorsement_id,
            call_id=call.call_id,
            tool=call.tool,
            card_text=text,
            remaining_approvals=card.remaining_approvals,
        )
        desk.open(pending)
        diagnostic(
            f"{endorsement_id}: {call.tool} (call {call.call_id}) waits for the user "
            f"({card.remaining_approvals} approval(s) left, {desk.timeout_seconds:g} s)\n"
            f"{text}\n{self._control_hint.replace('{id}', endorsement_id)}".rstrip()
        )
        elicitation = None
        ask = self._ask
        if ask is not None and self._elicitation and self._client_elicits:
            diagnostic(f"{endorsement_id}: also asking the user through the client (elicitation)")
            elicitation = _Elicitation(ask, desk, pending)
        try:
            answer = desk.resolve(
                endorsement_id,
                cancelled=lambda: self._cancelled(request_id),
                closed=self._input_closed,
            )
        finally:
            if elicitation is not None:
                elicitation.stop()
                if elicitation.failure is not None:
                    self._elicit_failures[endorsement_id] = elicitation.failure
        if answer.choice == "reject":
            return self._rejected(call, outcome, answer)
        values = self._gateway.store.as_mapping()
        units: dict[str, DecisionUnit | None] = {}
        for param, ref in card.proposal.args.items():
            value = values.get(ref.id)
            units[param] = None if value is None else value.unit
        entries = approval_entries(
            endorsement_id, card.endorsement.card, card.proposal, values, units
        )
        if isinstance(entries, str):
            diagnostic(
                f"{endorsement_id}: approved by the user but refused: {ERR_BAD_APPROVAL_ROW}"
            )
            return self._rejected(call, outcome, Answer("reject", "user"), bad_row=True)
        approved = self._gateway.approve(endorsement_id, entries)
        if approved is None:
            return _text_result(
                f"NOTARY blocked {call.tool}: the endorsement is gone", is_error=True
            )
        self._approved.append(endorsement_id)
        diagnostic(f"{endorsement_id}: approved by the user; the call is decided again")
        if approved.status == "blocked" and approved.error is not None:
            diagnostic(f"{endorsement_id}: the approval was not applied: {quoted(approved.error)}")
            return _text_result(
                f"NOTARY blocked {call.tool}: the endorsement could not be applied; "
                "it did not run.",
                is_error=True,
            )
        return self._answer(call, approved)

    def _rejected(
        self,
        call: RawCall,
        outcome: MediationOutcome,
        answer: Answer,
        *,
        disabled: bool = False,
        bad_row: bool = False,
    ) -> JsonObject:
        """Close the card without any effect and tell the agent why (the Gateway logs nothing)."""
        endorsement_id = outcome.endorsement_id
        if endorsement_id is not None:
            self._gateway.reject(endorsement_id)
            failed = self._elicit_failures.get(endorsement_id)
            cause = (
                "disabled"
                if disabled
                else "card mismatch"
                if bad_row
                else failed[0]
                if failed is not None and answer.cause == "user"
                else answer.cause
            )
            self._rejected_ids.append((endorsement_id, cause))
        if disabled:
            # Today's "escalated" answer with its reasons, now final: the card is closed.
            why = "approvals are disabled, so the endorsement was rejected"
            diagnostic(f"{endorsement_id}: rejected (disabled): {why}")
            return _text_result(
                f"NOTARY escalated {call.tool} ({endorsement_id}): it needs the user's "
                f"endorsement and did not run ({why}).\n{_reasons(outcome.decision)}".rstrip(),
                is_error=True,
            )
        if bad_row:
            why = "the endorsement card did not match the call, so it was rejected"
        elif answer.cause == "timeout":
            seconds = 0.0 if self._desk is None else self._desk.timeout_seconds
            why = f"no answer within {seconds:g} s"
        elif answer.cause == "user" and endorsement_id in self._elicit_failures:
            why = self._elicit_failures[endorsement_id][1]
        elif answer.cause == "user":
            why = "the user rejected the endorsement"
        else:
            why = "the request ended before the user answered"
        diagnostic(f"{endorsement_id}: rejected ({answer.cause}): {why}")
        return _text_result(f"NOTARY blocked {call.tool}: {why}", is_error=True)

    def on_server_notification(self, method: str, params: JsonObject) -> None:
        """Called on the client's reader thread: a changed tool list triggers a drift check.

        The check needs `tools/list`, which the reader thread cannot wait for, and it reads the
        Gateway, which one thread owns. With a `Dispatcher` the check is queued behind the calls
        already waiting and runs on its worker (`route_drift_checks`); without one (in-process
        tests) a small thread of its own runs it. Requests are coalesced either way.
        """
        if method in IGNORED_NOTIFICATIONS:
            # Not forwarded: the agent's view of resources and prompts stays the pinned one.
            diagnostic(f"{method}: ignored (resources and prompts are not re-listed)")
            return
        if method != LIST_CHANGED:
            return
        schedule = self._schedule_drift
        if schedule is not None:
            schedule()
            return
        if self._drift_worker is None:
            self._drift_worker = threading.Thread(
                target=self._drift_loop, name="drift-check", daemon=True
            )
            self._drift_worker.start()
        self._drift_requests.put(None)

    def route_cancellation(
        self, cancelled: Callable[[JsonValue], bool], input_closed: Callable[[], bool]
    ) -> None:
        """Let a call that waits for the user see the agent's cancel and the end of its input."""
        self._cancelled = cancelled
        self._input_closed = input_closed

    def route_client_requests(self, ask: ClientAsker) -> None:
        """Let a waiting call put its card to the user through the client (`ask_client`)."""
        self._ask = ask

    def route_user_prompts(self, submit: PromptSubmitter) -> None:
        """Let the control socket's thread hand a prompt to the Gateway's owner (`submit`)."""
        self._submit_prompt = submit

    def submit_user_prompt(self, text: str) -> str | None:
        """Called on the control socket's thread: the id of the stored prompt, None when not stored.

        Not stored when no `Dispatcher` routes the worker's queue yet (the Gateway may only be
        touched by its owner, so this never applies the prompt itself), and for the reasons in
        `Dispatcher.submit_user_prompt`.
        """
        submit = self._submit_prompt
        if submit is None:
            return None
        if self._compiler is None:
            return submit(text)
        return submit(text, run_timeout=COMPILING_PROMPT_WAIT)

    def add_user_prompt(self, text: str) -> str | None:
        """Store the prompt as a trusted user value. Only the thread that owns the Gateway.

        The first prompt of a run with a `prompt_compiler`, if nothing has started the run yet,
        is compiled first (a bounded request, `COMPILE_TIMEOUT`) and a narrower contract replaces
        the config's before `run_started` is written. Every failure keeps the config contract.
        """
        compiler, self._compiler = self._compiler, None  # only the first prompt compiles
        if compiler is not None and not self._gateway.chain and self._gateway.halted is None:
            self._adopt(compiler.compile(text))
        ref = self._gateway.add_user_value(text)
        if ref is None:
            diagnostic("user prompt: refused (the gateway is halted or the log failed)")
            return None
        # Never the text: stderr is not where the prompt belongs.
        diagnostic(f"user prompt: stored as {ref.id} ({len(text)} characters, trusted)")
        return ref.id

    def _adopt(self, contract: IntentContract | None) -> None:
        if contract is None:
            return
        try:
            self._gateway.adopt_contract(contract)
        except (ValueError, ContractWideningError) as failure:
            # `narrow` already checked; this is the Gateway's own guard (a chain that started).
            diagnostic(f"compile: kept the config contract: {type(failure).__name__}")

    def route_drift_checks(self, schedule: Callable[[], None]) -> None:
        """Queue drift checks with the Gateway's owner: `schedule` queues a `check_drift_now`."""
        self._schedule_drift = schedule

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
                self.check_drift_now()
            finally:
                for _ in range(extra + 1):
                    self._drift_requests.task_done()

    def check_drift_now(self) -> None:
        """Compare the pins with the server's tool list now and report on stderr."""
        if self._compiler is not None:
            self._begin_run()
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
            # Only reachable through `_answer` directly: `_call` waits for the user instead.
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
        records = self._record_values(call)
        if any(pattern.fullmatch(value.ref.id) is None for value in records):
            return _Labeled([], _records_object(call.call_id, records))
        texts = [blocks[name] for name in sorted(blocks)]
        if not leaves:
            return _Labeled(texts, None)
        rebuilt = as_object(unflatten(leaves_from(leaves, kinds)))
        if rebuilt is None:
            raise StructureError("structured content is not an object")
        return _Labeled(texts, rebuilt)

    def _record_values(self, call: RawCall) -> list[ResolvedValue]:
        """The values the call's tool result was labeled into, in the order they were logged.

        These are the `value_labeled` events after the call's last decision whose id starts with
        `<call_id>.`: arguments are labeled before the decision, so they are not among them.
        """
        chain = self._gateway.chain
        last = max(
            (
                index
                for index, entry in enumerate(chain)
                if isinstance(entry.event, DecisionMade) and entry.event.call_id == call.call_id
            ),
            default=-1,
        )
        found: list[ResolvedValue] = []
        for entry in chain[last + 1 :]:
            event = entry.event
            if isinstance(event, ValueLabeled) and event.value.id.startswith(f"{call.call_id}."):
                value = self._gateway.store.get(event.value.id)
                if value is not None:
                    found.append(value)
        return found


def _records_object(call_id: str, values: Sequence[ResolvedValue]) -> JsonObject:
    """The records-mode result as `{"records": [...]}`, rebuilt from the logged values only.

    A value id is `<call_id>.<record_id>.<field>`; the split is at the last dot (a field name
    with a dot would be shown in the record id, never lost). Each record's readers are those
    logged on its values (the backend labels a record's fields alike).
    """
    records: dict[str, JsonObject] = {}
    for value in values:
        record_id, _, name = value.ref.id[len(call_id) + 1 :].rpartition(".")
        record = records.setdefault(
            record_id,
            {"record_id": record_id, "readers": list(value.ref.label.readers), "fields": []},
        )
        fields = record["fields"]
        if isinstance(fields, list):
            fields.append({"name": name, "text": value.text, "unit": value.unit})
    return {"records": list(records.values())}


def serve(server: ProxyServer, reader: IO[bytes], writer: IO[bytes]) -> None:
    """Answer messages until the agent closes the stream (see `Dispatcher`)."""
    Dispatcher(server, reader, writer).run()
