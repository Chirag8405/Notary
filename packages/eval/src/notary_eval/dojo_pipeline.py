"""AgentDojo pipeline elements: a lane's tool step, a scripted LLM, a call-counting wrapper.

AgentDojo only ever calls `element.query(query, runtime, env, messages, extra_args)` on a pipeline
element, so these classes do not inherit from its `BasePipelineElement` (which would force a hard
import of the package): they follow the same shape. Messages are plain dicts, as AgentDojo's are.
The few AgentDojo objects needed (a `FunctionCall`, the output formatter) are passed in.
"""

import ast
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, cast

from pydantic import JsonValue

from notary_eval.dojo_guard import Dispatch, ExecResult, LaneStats
from notary_eval.dojo_types import DojoCall

Message = Mapping[str, object]
Extra = Mapping[str, object]


class ToolCall(Protocol):
    function: str
    args: dict[str, JsonValue]
    id: str | None


class Runtime(Protocol):
    functions: Mapping[str, object]

    def run_function(
        self,
        env: object | None,
        function: str,
        kwargs: Mapping[str, JsonValue],
        raise_on_error: bool,
    ) -> tuple[object, str | None]: ...


QueryResult = tuple[str, Runtime, object | None, Sequence[Message], Extra]
DispatchFactory = Callable[[Callable[[str, Mapping[str, JsonValue]], ExecResult]], Dispatch]


def text_block(text: str) -> dict[str, str]:
    return {"type": "text", "content": text}


def _string_list(value: str) -> list[JsonValue] | None:
    """AgentDojo turns an argument like "['a', 'b']" into a list before running the tool."""
    try:
        parsed = cast(object, ast.literal_eval(value))
    except (ValueError, SyntaxError):
        return None
    return cast(list[JsonValue], parsed) if isinstance(parsed, list) else None


class DispatchExecutor:
    """Runs the tool calls of the last assistant message through a lane's dispatcher.

    It stands where AgentDojo's `ToolsExecutor` stands and answers in the same message shape. The
    dispatcher is built on the first call, when the runtime and the environment of the task exist.
    """

    name: str | None = "dispatch-executor"

    def __init__(self, factory: DispatchFactory, format_result: Callable[[object], str]) -> None:
        self._factory = factory
        self._format = format_result
        self._dispatch: Dispatch | None = None
        self.not_run: list[object] = []
        """The tool calls (by identity) a lane refused: proposed, never executed."""

    @property
    def stats(self) -> LaneStats:
        return self._dispatch.stats if self._dispatch is not None else LaneStats()

    def _built(self, runtime: Runtime, env: object | None) -> Dispatch:
        if self._dispatch is None:

            def execute(tool: str, args: Mapping[str, JsonValue]) -> ExecResult:
                result, error = runtime.run_function(env, tool, args, False)
                return ExecResult("" if error is not None else self._format(result), error)

            self._dispatch = self._factory(execute)
        return self._dispatch

    def query(
        self,
        query: str,
        runtime: Runtime,
        env: object | None = None,
        messages: Sequence[Message] = (),
        extra_args: Extra | None = None,
    ) -> QueryResult:
        extra = extra_args or {}
        if not messages or messages[-1].get("role") != "assistant":
            return query, runtime, env, messages, extra
        calls = cast(Sequence[ToolCall] | None, messages[-1].get("tool_calls")) or ()
        if not calls:
            return query, runtime, env, messages, extra
        dispatch = self._built(runtime, env)
        results: list[Message] = []
        for call in calls:
            if call.function not in runtime.functions:
                text, error = "", f"Invalid tool {call.function} provided."
            else:
                for name, value in list(call.args.items()):
                    if isinstance(value, str) and (as_list := _string_list(value)) is not None:
                        call.args[name] = as_list
                reply = dispatch(call.function, call.args)
                text, error = reply.text, reply.error
                if not reply.executed:
                    self.not_run.append(call)
            results.append(
                {
                    "role": "tool",
                    "content": [text_block(text)],
                    "tool_call_id": call.id,
                    "tool_call": call,
                    "error": error,
                }
            )
        return query, runtime, env, [*messages, *results], extra


class ScriptedLLM:
    """A pipeline element that plays a fixed list of tool calls, one per turn (no model call)."""

    name: str | None = "scripted"

    def __init__(self, calls: Sequence[DojoCall], make_call: Callable[..., object]) -> None:
        self._calls = tuple(calls)
        self._make = make_call
        self.model_calls = 0

    def query(
        self,
        query: str,
        runtime: Runtime,
        env: object | None = None,
        messages: Sequence[Message] = (),
        extra_args: Extra | None = None,
    ) -> QueryResult:
        done = sum(1 for m in messages if m.get("role") == "tool")
        if done < len(self._calls):
            call = self._calls[done]
            made = self._make(function=call.function, args=dict(call.args), id=f"call_{done}")
            reply: Message = {"role": "assistant", "content": None, "tool_calls": [made]}
        else:
            reply = {"role": "assistant", "content": [text_block("Done.")], "tool_calls": None}
        return query, runtime, env, [*messages, reply], extra_args or {}


class Querying(Protocol):
    def query(
        self,
        query: str,
        runtime: Runtime,
        env: object | None,
        messages: Sequence[Message],
        extra_args: Extra,
    ) -> QueryResult: ...


class CountingLLM:
    """Wraps a real LLM element and counts its calls (the cost the report states)."""

    def __init__(self, inner: Querying, name: str) -> None:
        self._inner = inner
        self.name: str | None = name
        self.model_calls = 0

    def query(
        self,
        query: str,
        runtime: Runtime,
        env: object | None = None,
        messages: Sequence[Message] = (),
        extra_args: Extra | None = None,
    ) -> QueryResult:
        self.model_calls += 1
        return self._inner.query(query, runtime, env, messages, extra_args or {})


class ExecutedOnly:
    """Wraps a whole pipeline so the run's history lists only the calls that were executed.

    AgentDojo judges a few tasks from the TRACE of tool calls the agent proposed
    (`security_from_traces`, `utility_from_traces`), not from the environment. A call a defence
    refused never happened, so it must not count as an attack that succeeded (or a task that was
    done). Applied to the final history only; the model has already seen the refusals.
    """

    name: str | None = "executed-only"

    def __init__(self, inner: Querying, executor: DispatchExecutor) -> None:
        self._inner = inner
        self._executor = executor

    def query(
        self,
        query: str,
        runtime: Runtime,
        env: object | None = None,
        messages: Sequence[Message] = (),
        extra_args: Extra | None = None,
    ) -> QueryResult:
        out_query, out_runtime, out_env, history, extra = self._inner.query(
            query, runtime, env, messages, extra_args or {}
        )
        refused = {id(call) for call in self._executor.not_run}
        kept: list[Message] = []
        for message in history:
            calls = cast(Sequence[object] | None, message.get("tool_calls"))
            if message.get("role") == "assistant" and calls:
                kept.append({**message, "tool_calls": [c for c in calls if id(c) not in refused]})
            else:
                kept.append(message)
        return out_query, out_runtime, out_env, kept, extra
