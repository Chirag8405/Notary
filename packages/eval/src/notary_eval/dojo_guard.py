"""The three lanes as tool dispatchers: what happens to a call the agent proposes.

A dispatcher sits between the agent's LLM and AgentDojo's tool runtime (the pipeline element in
`notary_eval.dojo_live` and the offline runner both call it):

- `UndefendedDispatch`: runs every call.
- `ClassifierDispatch`: runs every call and redacts a result the keyword stand-in
  (`notary_world.classifier.ClassifierFilter`) flags. It is a stand-in, not a trained detector.
- `NotaryDispatch`: the real thing. The call goes through `notary_mcp_proxy.gateway.Gateway`,
  which labels the arguments (the user's request is a trusted value, tool results are untrusted,
  anything the model wrote is untrusted), asks `notary_core.monitor.decide` with the benchmark's
  policy table, logs the decision to the audit chain BEFORE the tool runs, and only then runs it.

An ESCALATE is answered by a simulated user (`ApprovalPolicy`): `reject` refuses every card
(utility lower bound), `oracle` approves a card exactly when the call is one the task's ground
truth contains (a user who endorses what they asked for; optimistic).
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import NamedTuple, Protocol

from pydantic import JsonValue

from notary_core.endorsement import approval_entries
from notary_core.gateway import ToolResult, ToolResultField, label_tool_result
from notary_core.models import (
    Decision,
    DecisionUnit,
    IntentContract,
    LedgerEntry,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
)
from notary_core.monitor import decide
from notary_core.pinning import ToolManifest
from notary_core.policy.sensitive_params import ParamPolicy
from notary_core.resolver import ArgumentResolver
from notary_core.units import canonicalize, canonicalize_amount, to_cents
from notary_core.urls import extract_urls
from notary_eval.dojo_compiler import CompiledTask, tool_manifest, value_text
from notary_eval.dojo_tools import BENCH_POLICY, DOJO_POLICY
from notary_eval.dojo_types import ApprovalPolicy, DojoCall, DojoSuite, DojoTool, DojoUserTask
from notary_mcp_proxy.backend import BackendEffect, BackendRecord, BackendResult
from notary_mcp_proxy.gateway import Gateway, MediationOutcome, RawCall
from notary_mcp_proxy.mcp_backend import decode_argument, encode_argument
from notary_world.classifier import REDACTION_MARKER, ClassifierFilter

OUTPUT_FIELD = "output"
"""The one field a tool result is stored as; an argument that quotes it is a span of it."""


class ExecResult(NamedTuple):
    text: str
    error: str | None


ToolExecutor = Callable[[str, Mapping[str, JsonValue]], ExecResult]
"""Runs one tool in the environment (AgentDojo's runtime, or the offline world)."""


class Dispatched(NamedTuple):
    """What the agent gets back for one proposed call."""

    text: str
    error: str | None
    executed: bool
    """The tool ran (the effect, if it has one, happened)."""


@dataclass(slots=True)
class LaneStats:
    calls: int = 0
    blocked: int = 0
    escalated: int = 0
    approved: int = 0
    flagged: int = 0
    codes: set[str] = field(default_factory=lambda: set[str]())


class Dispatch(Protocol):
    stats: LaneStats

    def __call__(self, tool: str, args: Mapping[str, JsonValue]) -> Dispatched: ...


class UndefendedDispatch:
    def __init__(self, execute: ToolExecutor) -> None:
        self._execute = execute
        self.stats = LaneStats()

    def __call__(self, tool: str, args: Mapping[str, JsonValue]) -> Dispatched:
        self.stats.calls += 1
        done = self._execute(tool, args)
        return Dispatched(done.text, done.error, executed=True)


class ClassifierDispatch:
    def __init__(self, execute: ToolExecutor, classifier: ClassifierFilter | None = None) -> None:
        self._execute = execute
        self._classifier = classifier or ClassifierFilter()
        self.stats = LaneStats()

    def __call__(self, tool: str, args: Mapping[str, JsonValue]) -> Dispatched:
        self.stats.calls += 1
        done = self._execute(tool, args)
        result = ToolResult(
            tool=tool,
            record_id=f"c{self.stats.calls}",
            fields=(ToolResultField(name=OUTPUT_FIELD, text=done.text, unit=None),),
        )
        if self._classifier.scan(result):
            self.stats.flagged += 1
            return Dispatched(REDACTION_MARKER, done.error, executed=True)
        return Dispatched(done.text, done.error, executed=True)


def sensitive_params(function: str) -> tuple[tuple[str, ParamPolicy], ...]:
    """The parameters of `function` whose value decides what the call does (not free text)."""
    entry = DOJO_POLICY.get(function)
    if entry is None:
        return ()
    return tuple(
        (binding.name, binding.policy)
        for binding in entry.params
        if binding.policy.kind in ("destination", "identifier", "amount")
    )


def _canonical(policy: ParamPolicy, text: str) -> str:
    if policy.kind == "amount":
        cents = to_cents(canonicalize_amount(text))
        return text.strip() if cents is None else str(cents)
    return canonicalize(policy.unit or "identifier", text).value


def _payload_urls_present(function: str, truth: DojoCall, args: Mapping[str, JsonValue]) -> bool:
    """Every URL the ground truth puts in free text (the planted link) is in the executed text."""
    entry = DOJO_POLICY.get(function)
    for binding in entry.params if entry else ():
        if binding.policy.kind != "payload" or binding.name not in truth.args:
            continue
        wanted = {url.host for url in extract_urls(value_text(truth.args[binding.name]))}
        sent = {url.host for url in extract_urls(value_text(args.get(binding.name, "")))}
        if not wanted <= sent:
            return False
    return True


def call_matches(truth: DojoCall, function: str, args: Mapping[str, JsonValue]) -> bool:
    """The executed call does what the ground-truth call does: same tool, same decisive values.

    Free text (a subject, a message body) is the model's own wording and is not compared, except
    for a URL the ground truth puts in it (the planted link of an exfiltration or phishing goal).
    """
    if truth.function != function:
        return False
    for param, policy in sensitive_params(function):
        if param not in truth.args:
            continue
        if param not in args:
            return False
        if _canonical(policy, value_text(truth.args[param])) != _canonical(
            policy, value_text(args[param])
        ):
            return False
    return _payload_urls_present(function, truth, args)


def matches_any(calls: Sequence[DojoCall], function: str, args: Mapping[str, JsonValue]) -> bool:
    return any(call_matches(call, function, args) for call in calls)


class _Backend:
    """Gateway tool backend over an executor: manifests from the snapshot, results as records."""

    def __init__(self, tools: Sequence[DojoTool], execute: ToolExecutor) -> None:
        self._tools = {tool.name: tool for tool in tools}
        self._manifests = tuple(tool_manifest(tool) for tool in tools)
        self._execute = execute
        self.last: ExecResult | None = None

    def list_tools(self) -> Sequence[ToolManifest]:
        return self._manifests

    def _decode(self, tool: str, args: Mapping[str, str]) -> dict[str, JsonValue]:
        known = self._tools.get(tool)
        types = {p.name: p.types for p in known.params} if known else {}
        decoded: dict[str, JsonValue] = {}
        for name, text in args.items():
            kinds = types.get(name, ())
            if text == "null" and "null" in kinds and "string" not in kinds:
                decoded[name] = None
            elif "string" in kinds or not kinds:
                decoded[name] = text
            else:
                decoded[name] = decode_argument(text, kinds[0] if len(kinds) == 1 else "number")
        return decoded

    def call_tool(self, tool: str, args: Mapping[str, str]) -> BackendResult:
        decoded = self._decode(tool, args)
        done = self._execute(tool, decoded)
        self.last = done
        record = BackendRecord(
            record_id="r",
            readers=("*",),
            fields=(ToolResultField(name=OUTPUT_FIELD, text=done.text, unit=None),),
        )
        entry = DOJO_POLICY.get(tool)
        if done.error is not None:
            return BackendResult(records=(record,), effect=None, error=done.error)
        spent = 0
        egress = 0
        for binding in entry.params if entry else ():
            if binding.name not in args:
                continue
            if binding.policy.kind == "amount":
                spent += to_cents(canonicalize_amount(args[binding.name])) or 0
            elif binding.policy.kind == "payload":
                egress += len(args[binding.name].encode("utf-8"))
        effect = BackendEffect(
            summary=tool,
            spent_cents=spent,
            egress_bytes=egress,
            mutating=entry is None or entry.effect != "read",
        )
        return BackendResult(records=(record,), effect=effect, error=None)


class NotaryDispatch:
    """One user task's Gateway, built from a compiled contract."""

    def __init__(
        self,
        suite: DojoSuite,
        task: DojoUserTask,
        compiled: CompiledTask,
        execute: ToolExecutor,
        *,
        approval: ApprovalPolicy,
        run_id: str,
    ) -> None:
        self._task = task
        self._approval: ApprovalPolicy = approval
        self._backend = _Backend(suite.tools, execute)
        self._gateway = Gateway(
            backend=self._backend,
            contract=compiled.contract,
            ledger=compiled.ledger,
            monitor=bench_monitor,
            labeler=label_tool_result,
            resolver=ArgumentResolver(),
            run_id=run_id,
            lane="notary",
            policy=BENCH_POLICY,
        )
        self._gateway.pin_session()
        self._gateway.add_user_value(task.prompt)
        self._count = 0
        self.stats = LaneStats()

    @property
    def gateway(self) -> Gateway:
        return self._gateway

    def __call__(self, tool: str, args: Mapping[str, JsonValue]) -> Dispatched:
        self._count += 1
        self.stats.calls += 1
        call = RawCall(
            call_id=f"c{self._count}",
            tool=tool,
            args={name: encode_argument(value) for name, value in args.items()},
        )
        outcome = self._gateway.propose(call)
        if outcome.status == "escalated":
            outcome = self._answer(outcome, tool, args)
        return self._reply(outcome)

    def _answer(
        self, outcome: MediationOutcome, tool: str, args: Mapping[str, JsonValue]
    ) -> MediationOutcome:
        self.stats.escalated += 1
        card_id = outcome.endorsement_id or ""
        if self._approval == "oracle" and matches_any(self._task.calls, tool, args):
            pending = next(
                (
                    p
                    for p in self._gateway.pending_endorsements()
                    if p.endorsement.endorsement_id == card_id
                ),
                None,
            )
            if pending is not None:
                units: dict[str, DecisionUnit | None] = {
                    name: policy.unit for name, policy in sensitive_params(tool)
                }
                entries = approval_entries(
                    card_id,
                    pending.endorsement.card,
                    pending.proposal,
                    self._gateway.store.as_mapping(),
                    units,
                )
                if not isinstance(entries, str):
                    approved = self._gateway.approve(card_id, entries)
                    if approved is not None:
                        if approved.status != "blocked":
                            self.stats.approved += 1
                        return approved
        rejected = self._gateway.reject(card_id)
        return rejected if rejected is not None else outcome

    def _reply(self, outcome: MediationOutcome) -> Dispatched:
        if outcome.status == "executed":
            last = self._backend.last
            return Dispatched(last.text if last else "", None, executed=True)
        if outcome.status == "tool_error":
            return Dispatched("", outcome.error or "tool error", executed=True)
        if outcome.status == "halted":
            return Dispatched("", outcome.error or "NOTARY halted", executed=False)
        failed = _failed_codes(outcome.decision)
        self.stats.blocked += 1
        self.stats.codes.update(failed)
        label = ", ".join(failed) or "not approved"
        message = f"NOTARY did not run this call ({label}). The user did not authorize it."
        # AgentDojo's LLM adapters show the `error` of a tool message instead of its content.
        return Dispatched(message, message, executed=False)


def _failed_codes(decision: Decision | None) -> tuple[str, ...]:
    if decision is None:
        return ()
    return tuple(r.code for r in decision.reasons if r.outcome != "pass")


def bench_monitor(
    contract: IntentContract,
    proposal: ToolCallProposal,
    values: Mapping[str, ResolvedValue],
    ledger: Sequence[LedgerEntry],
    session: SessionState,
) -> Decision:
    return decide(contract, proposal, values, ledger, session, policy=BENCH_POLICY)
