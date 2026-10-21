"""The only code that touches the real `agentdojo` package (imported lazily, behind Protocols).

AgentDojo is untyped, so every object it hands back is cast to a small `Protocol` of just the
members used here. Nothing in this module runs at import time; `agentdojo` is not a dependency of
the repo (see docs/decisions.md): install it for one command with
`uv run --no-sync --with agentdojo==0.1.35 ...`.

- `build_snapshot` copies the banking and Slack suites into a `DojoSnapshot` (the offline harness
  and the committed fixture run on that copy).
- `LivePipelines` builds AgentDojo pipelines whose tool step is a lane dispatcher
  (`notary_eval.dojo_guard`), with either a scripted LLM (no model calls) or a real one.
- `run_live_task` runs one task through `suite.run_task_with_pipeline`, AgentDojo's own checker.
"""

import importlib
import importlib.util
import json
import re
from collections.abc import Callable, Mapping, Sequence
from types import ModuleType
from typing import Protocol, cast

from pydantic import JsonValue

from notary_eval.dojo_types import (
    SNAPSHOT_FORMAT,
    DojoCall,
    DojoInjectionTask,
    DojoLedgerSeed,
    DojoParam,
    DojoSnapshot,
    DojoSuite,
    DojoTool,
    DojoUserTask,
)

PINNED_VERSION = "0.1.35"
DEFAULT_BENCHMARK = "v1.2.2"
LICENCE = (
    "AgentDojo (c) ETH SPY Lab, MIT licence, https://github.com/ethz-spylab/agentdojo. "
    "Tasks, prompts and ground-truth calls are copied from the package for offline tests."
)
INJECTION_USER = "Emma Johnson"
INJECTION_MODEL = "the AI language model"


class AgentDojoMissingError(RuntimeError):
    """The optional `agentdojo` package is not installed."""


def agentdojo_available() -> bool:
    return importlib.util.find_spec("agentdojo") is not None


def agentdojo_version() -> str:
    from importlib import metadata

    try:
        return metadata.version("agentdojo")
    except metadata.PackageNotFoundError as missing:
        raise AgentDojoMissingError(_INSTALL) from missing


_INSTALL = (
    "the 'agentdojo' package is not installed; run this command with "
    f"`uv run --no-sync --with agentdojo=={PINNED_VERSION} ...` "
    "(it is not a dependency of the repo)"
)


def import_module(name: str) -> ModuleType:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as missing:
        if missing.name is not None and missing.name.split(".")[0] == "agentdojo":
            raise AgentDojoMissingError(_INSTALL) from missing
        raise


def attr(module: ModuleType, name: str) -> object:
    return cast(object, getattr(module, name))


# -- typed views of the parts of AgentDojo this module uses ---------------------------------------


class _CallLike(Protocol):
    function: str
    args: Mapping[str, JsonValue]


class _ModelClass(Protocol):
    def model_json_schema(self) -> dict[str, JsonValue]: ...


class _FunctionLike(Protocol):
    name: str
    description: str
    parameters: _ModelClass


class EnvLike(Protocol):
    def model_copy(self, *, deep: bool) -> "EnvLike": ...

    def model_dump(self) -> dict[str, JsonValue]: ...


class _UserTaskLike(Protocol):
    ID: str
    PROMPT: str

    def ground_truth(self, pre_environment: EnvLike) -> Sequence[_CallLike]: ...

    def init_environment(self, environment: EnvLike) -> EnvLike: ...


class _InjectionTaskLike(Protocol):
    ID: str
    GOAL: str

    def ground_truth(self, pre_environment: EnvLike) -> Sequence[_CallLike]: ...


class RuntimeLike(Protocol):
    functions: Mapping[str, object]

    def run_function(
        self,
        env: EnvLike | None,
        function: str,
        kwargs: Mapping[str, JsonValue],
        raise_on_error: bool,
    ) -> tuple[object, str | None]: ...


class SuiteLike(Protocol):
    name: str

    @property
    def user_tasks(self) -> Mapping[str, _UserTaskLike]: ...

    @property
    def injection_tasks(self) -> Mapping[str, _InjectionTaskLike]: ...

    @property
    def tools(self) -> Sequence[_FunctionLike]: ...

    def load_and_inject_default_environment(self, injections: Mapping[str, str]) -> EnvLike: ...

    def run_task_with_pipeline(
        self,
        agent_pipeline: object,
        user_task: _UserTaskLike,
        injection_task: _InjectionTaskLike | None,
        injections: Mapping[str, str],
    ) -> tuple[bool, bool]: ...


def load_suite(name: str, benchmark: str = DEFAULT_BENCHMARK) -> SuiteLike:
    module = import_module("agentdojo.task_suite.load_suites")
    getter = cast(Callable[[str, str], SuiteLike], attr(module, "get_suite"))
    return getter(benchmark, name)


def output_formatter() -> Callable[[object], str]:
    module = import_module("agentdojo.agent_pipeline.tool_execution")
    return cast(Callable[[object], str], attr(module, "tool_result_to_str"))


def _runtime(suite: SuiteLike) -> RuntimeLike:
    module = import_module("agentdojo.functions_runtime")
    factory = cast(
        Callable[[Sequence[_FunctionLike]], RuntimeLike], attr(module, "FunctionsRuntime")
    )
    return factory(suite.tools)


# -- the snapshot -------------------------------------------------------------------------------


def _schema_types(prop: JsonValue) -> tuple[str, ...]:
    if not isinstance(prop, dict):
        return ()
    kind = prop.get("type")
    found: list[str] = [kind] if isinstance(kind, str) else []
    options = prop.get("anyOf")
    if isinstance(options, list):
        for option in options:
            found.extend(_schema_types(option))
    return tuple(dict.fromkeys(found))


def _tool(function: _FunctionLike) -> DojoTool:
    schema = function.parameters.model_json_schema()
    properties = schema.get("properties")
    names = list(properties) if isinstance(properties, dict) else []
    params = tuple(
        DojoParam(name=name, types=_schema_types(cast(dict[str, JsonValue], properties)[name]))
        for name in names
    )
    return DojoTool(
        name=function.name,
        description=function.description,
        input_schema=json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        params=params,
    )


def _calls(
    suite: SuiteLike, truth: Callable[[EnvLike], Sequence[_CallLike]], env: EnvLike
) -> tuple[DojoCall, ...]:
    """The ground-truth calls, each with the text the tool printed on a clean environment."""
    runtime = _runtime(suite)
    fmt = output_formatter()
    calls = truth(env.model_copy(deep=True))
    scratch = env.model_copy(deep=True)
    out: list[DojoCall] = []
    for call in calls:
        result, _ = runtime.run_function(scratch, call.function, call.args, True)
        out.append(DojoCall(function=call.function, args=dict(call.args), output=fmt(result)))
    return tuple(out)


def _rows(value: JsonValue | None) -> list[JsonValue]:
    return value if isinstance(value, list) else []


def _seeds(suite: str, env: EnvLike) -> tuple[DojoLedgerSeed, ...]:
    """The user's own state: past payees (banking), workspace members and channels (Slack)."""
    data = env.model_dump()
    seeds: list[DojoLedgerSeed] = []
    if suite == "banking":
        account = data.get("bank_account")
        if isinstance(account, dict):
            own = account.get("iban")
            rows = [
                *_rows(account.get("transactions")),
                *_rows(account.get("scheduled_transactions")),
            ]
            for row in rows:
                if not isinstance(row, dict):
                    continue
                recipient = row.get("recipient")
                if row.get("sender") in ("me", own) and isinstance(recipient, str):
                    seeds.append(
                        DojoLedgerSeed(
                            ledger="payees",
                            key=f"paid before: {recipient}",
                            value=recipient,
                            unit="iban",
                        )
                    )
    if suite == "slack":
        slack = data.get("slack")
        if isinstance(slack, dict):
            for ledger, field in (("contacts", "users"), ("channels", "channels")):
                names = slack.get(field)
                if isinstance(names, list):
                    seeds.extend(
                        DojoLedgerSeed(
                            ledger=ledger,
                            key=f"{field[:-1]}: {name}",
                            value=name,
                            unit="identifier",
                        )
                        for name in names
                        if isinstance(name, str)
                    )
    unique = {(s.ledger, s.value): s for s in seeds}
    return tuple(unique.values())


def _injection_text(goal: str) -> str:
    module = import_module("agentdojo.attacks.important_instructions_attacks")
    attack = cast(type, attr(module, "ImportantInstructionsAttack"))
    template = cast(str, vars(attack)["_JB_STRING"])
    return template.format(goal=goal, user=INJECTION_USER, model=INJECTION_MODEL)


def _number(task_id: str) -> int:
    return int(re.sub(r"\D", "", task_id) or "0")


def suite_snapshot(name: str, benchmark: str = DEFAULT_BENCHMARK) -> DojoSuite:
    suite = load_suite(name, benchmark)
    env = suite.load_and_inject_default_environment({})
    users = tuple(
        DojoUserTask(
            task_id=task_id,
            prompt=task.PROMPT,
            calls=_calls(
                suite, task.ground_truth, task.init_environment(env.model_copy(deep=True))
            ),
        )
        for task_id, task in sorted(suite.user_tasks.items(), key=lambda item: _number(item[0]))
    )
    attacks = tuple(
        DojoInjectionTask(
            task_id=task_id,
            goal=task.GOAL,
            injection_text=_injection_text(task.GOAL),
            calls=_calls(suite, task.ground_truth, env),
        )
        for task_id, task in sorted(
            suite.injection_tasks.items(), key=lambda item: _number(item[0])
        )
    )
    return DojoSuite(
        suite=name,
        tools=tuple(_tool(function) for function in suite.tools),
        user_tasks=users,
        injection_tasks=attacks,
        ledger=_seeds(name, env),
    )


def build_snapshot(suites: Sequence[str], benchmark: str = DEFAULT_BENCHMARK) -> DojoSnapshot:
    return DojoSnapshot(
        format=SNAPSHOT_FORMAT,
        benchmark=benchmark,
        agentdojo_version=agentdojo_version(),
        licence=LICENCE,
        suites=tuple(suite_snapshot(name, benchmark) for name in suites),
    )
