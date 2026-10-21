"""Compile an AgentDojo user task into an `IntentContract` (the benchmark's Intent Compiler).

The compiler here is an ORACLE-ASSISTED UPPER BOUND, not the product's compiler. It reads the
task's ground-truth tool calls (which the real compiler never sees) and derives:

- the tools in scope: every read tool of the suite, plus exactly the effect tools the ground truth
  calls (an unmapped tool is left out, so the monitor blocks it: fail closed);
- a marker for every parameter of those tools: a `literal` marker when the ground truth passes
  one value that the user typed in the request, else the table's floor (`ledger`, `endorse`,
  `free`); values the user typed that the ground truth uses more than once become trusted,
  user-authored ledger entries instead;
- a budget just big enough for the ground truth (effects +1, spend and per-call amount from the
  ground-truth amounts, a fixed egress allowance), `authorized_irreversible` for the irreversible
  tools it calls, and the hosts named in the request as the egress allowlist.

A contract built from the solution is tighter than anything a compiler reading only the request
can promise, so utility and attack numbers measured with it bound the real pipeline from the
optimistic side. `ContractCompiler` is the hook for the LLM compiler used elsewhere
(`notary_server.compiler`); the benchmark entry point can pass one in, and nothing else changes.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from pydantic import JsonValue

from notary_core.models import (
    EffectBudget,
    IntentContract,
    LedgerEntry,
    LedgerMarker,
    LiteralMarker,
    Marker,
    ToolScope,
)
from notary_core.pinning import ToolManifest, manifest_hash
from notary_core.policy.sensitive_params import ParamPolicy
from notary_core.units import canonicalize_amount, to_cents
from notary_core.urls import extract_urls
from notary_eval.dojo_tools import DOJO_POLICY
from notary_eval.dojo_types import (
    Bucket,
    DojoCall,
    DojoSuite,
    DojoTool,
    DojoUserTask,
)
from notary_mcp_proxy.mcp_backend import encode_argument
from notary_world.scenarios import make_ledger_entry

EGRESS_ALLOWANCE_BYTES = 65_536
"""Free text the agent may send in one task; the ground truth only has placeholders for it."""
REQUEST_LEDGER = "request"
"""Ledger of values the user typed in the request when the table's floor names no ledger."""
ACTION_OPEN: frozenset[tuple[str, str]] = frozenset(
    {("banking", "user_task_12"), ("slack", "user_task_18"), ("slack", "user_task_19")}
)
"""Tasks whose instructions themselves live in fetched content ("follow the instructions in the
file", "do the tasks on my TODO list"): the action is open, not only a parameter."""


@dataclass(frozen=True, slots=True)
class CompileOptions:
    effect_slack: int = 1
    """Effects allowed beyond the ground truth (a retried call)."""
    max_approvals: int = 3


@dataclass(frozen=True, slots=True)
class CompiledTask:
    contract: IntentContract
    ledger: tuple[LedgerEntry, ...]
    unmapped: tuple[str, ...]
    """Ground-truth tools the table does not map: left out of the contract."""
    bucket: Bucket


class ContractCompiler(Protocol):
    """The compiler hook: a task in, a contract and the trusted ledger out."""

    def __call__(self, suite: DojoSuite, task: DojoUserTask) -> CompiledTask: ...


def tool_manifest(tool: DojoTool) -> ToolManifest:
    return ToolManifest(
        name=tool.name, description=tool.description, input_schema=tool.input_schema
    )


def value_text(value: JsonValue) -> str:
    """How a ground-truth argument reads as the text the monitor sees."""
    return value if isinstance(value, str) else encode_argument(value)


def _policy_of(tool: str, param: str) -> ParamPolicy | None:
    entry = DOJO_POLICY.get(tool)
    if entry is None:
        return None
    return next((b.policy for b in entry.params if b.name == param), None)


def _is_typed_by_user(text: str, prompt: str) -> bool:
    return len(text) > 0 and text.casefold() in prompt.casefold()


def _cents(text: str) -> int:
    parsed = to_cents(canonicalize_amount(text))
    return 0 if parsed is None else parsed


def bucket_of(suite: str, task: DojoUserTask) -> Bucket:
    """fully-specified / parameter-open / action-open (read-only when no call has an effect)."""
    effect_calls = [call for call in task.calls if not _is_read(call.function)]
    if not effect_calls:
        return "read_only"
    if (suite, task.task_id) in ACTION_OPEN:
        return "action_open"
    for call in effect_calls:
        for param, value in call.args.items():
            policy = _policy_of(call.function, param)
            if policy is None or policy.kind not in ("destination", "identifier"):
                continue
            if not _is_typed_by_user(value_text(value), task.prompt):
                return "parameter_open"
    return "fully_specified"


def _scope_marker(policy: ParamPolicy, typed: Sequence[str]) -> Marker:
    """`literal` when the user typed the one value the ground truth passes, else the floor."""
    if (
        len(typed) == 1
        and policy.kind in ("destination", "identifier")
        and policy.floor.kind != "free"
    ):
        return LiteralMarker(kind="literal", value=typed[0])
    return policy.floor


def _typed_values(calls: Sequence[DojoCall], prompt: str, tool: str, param: str) -> list[str]:
    """Distinct values the ground truth passes for `tool.param` that the user typed (in order)."""
    seen: list[str] = []
    for call in calls:
        if call.function != tool or param not in call.args:
            continue
        text = value_text(call.args[param])
        if _is_typed_by_user(text, prompt) and text not in seen:
            seen.append(text)
    return seen


def compile_oracle(
    suite: DojoSuite, task: DojoUserTask, options: CompileOptions | None = None
) -> CompiledTask:
    """The oracle-assisted contract of `task` (see the module docstring)."""
    options = options or CompileOptions()
    tools = {tool.name: tool for tool in suite.tools}
    ground_truth = [call for call in task.calls if call.function in tools]
    unmapped = tuple(sorted({c.function for c in task.calls if c.function not in DOJO_POLICY}))
    effect_tools = sorted(
        {c.function for c in ground_truth if c.function in DOJO_POLICY}
        - {name for name, entry in DOJO_POLICY.items() if entry.effect == "read"}
    )
    read_tools = sorted(name for name in tools if _is_read(name))
    scopes: list[ToolScope] = []
    entries: list[LedgerEntry] = []
    for index, seed in enumerate(suite.ledger):
        entries.append(
            make_ledger_entry(f"seed-{index}", seed.ledger, seed.key, seed.value, seed.unit)
        )
    for name in sorted({*read_tools, *effect_tools}):
        tool = tools[name]
        params: dict[str, Marker] = {}
        for declared in tool.params:
            policy = _policy_of(name, declared.name)
            if policy is None:
                continue
            typed = _typed_values(ground_truth, task.prompt, name, declared.name)
            if len(typed) > 1 and policy.kind in ("destination", "identifier"):
                ledger = policy.floor.ledger if isinstance(policy.floor, LedgerMarker) else None
                for value in typed:
                    entries.append(
                        make_ledger_entry(
                            f"req-{len(entries)}",
                            ledger or REQUEST_LEDGER,
                            f"{name}.{declared.name}: {value}",
                            value,
                            policy.unit or "identifier",
                        )
                    )
                params[declared.name] = policy.floor
            else:
                params[declared.name] = _scope_marker(policy, typed)
        effect = DOJO_POLICY[name].effect
        scopes.append(
            ToolScope(
                tool=name,
                params=params,
                manifest_hash=manifest_hash(tool_manifest(tool)),
                effect=effect,
            )
        )
    budget = _budget(ground_truth, options)
    contract = IntentContract(
        contract_id=f"dojo-{suite.suite}-{task.task_id}",
        user_intent=task.prompt,
        allowed_tools=tuple(scopes),
        budget=budget,
        egress_hosts=tuple(sorted({url.host for url in extract_urls(task.prompt)})),
        authorized_irreversible=tuple(
            name for name in effect_tools if DOJO_POLICY[name].effect == "irreversible"
        ),
    )
    return CompiledTask(
        contract=contract,
        ledger=_dedupe(entries),
        unmapped=unmapped,
        bucket=bucket_of(suite.suite, task),
    )


def _is_read(name: str) -> bool:
    entry = DOJO_POLICY.get(name)
    return entry is not None and entry.effect == "read"


def _dedupe(entries: Sequence[LedgerEntry]) -> tuple[LedgerEntry, ...]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[LedgerEntry] = []
    for entry in entries:
        key = (entry.ledger, entry.unit, entry.canonical)
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return tuple(unique)


def _budget(ground_truth: Sequence[DojoCall], options: CompileOptions) -> EffectBudget:
    effects = 0
    spend = 0
    biggest = 0
    for call in ground_truth:
        entry = DOJO_POLICY.get(call.function)
        if entry is None or entry.effect == "read":
            continue
        effects += 1
        total = 0
        for binding in entry.params:
            if binding.policy.kind == "amount" and binding.name in call.args:
                total += _cents(value_text(call.args[binding.name]))
        spend += total
        biggest = max(biggest, total)
    return EffectBudget(
        max_effects=effects + options.effect_slack,
        max_spend_cents=spend,
        max_egress_bytes=EGRESS_ALLOWANCE_BYTES,
        max_call_amount_cents=biggest,
        max_approvals=options.max_approvals,
    )
