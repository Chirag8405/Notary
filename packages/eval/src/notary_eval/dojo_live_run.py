"""Run AgentDojo tasks in AgentDojo's own environment and checkers (needs `agentdojo`).

Two agents: `scripted` (the same fixed calls as the offline run, no model call, free) and `model`
(a real LLM, which costs money and needs a key in the environment; the CLI guards it with
`--confirm-live`). Both go through `suite.run_task_with_pipeline`, so utility and attack success are
AgentDojo's own `utility()` and `security()` checks on the environment after the run.
"""

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from pydantic import JsonValue

from notary_eval.dojo_compiler import CompiledTask, compile_oracle
from notary_eval.dojo_guard import Dispatch, ExecResult
from notary_eval.dojo_live import (
    DEFAULT_BENCHMARK,
    SuiteLike,
    attr,
    import_module,
    load_suite,
    output_formatter,
)
from notary_eval.dojo_pipeline import (
    CountingLLM,
    DispatchExecutor,
    ExecutedOnly,
    Querying,
    ScriptedLLM,
)
from notary_eval.dojo_run import (
    Compile,
    RunConfig,
    RunSpec,
    failed_run,
    injection_reaches_agent,
    make_dispatch,
    plan_runs,
    scripted_calls,
)
from notary_eval.dojo_types import AgentKind, DojoRun, DojoSnapshot

GROQ_URL = "https://api.groq.com/openai/v1"
PROVIDER_KEYS: Mapping[str, str] = {
    "groq": "GROQ_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}
STUB_MODEL = "gpt-4o-2024-05-13"
"""A name AgentDojo's attack classes accept; the attack text is made model-neutral afterwards."""
DEFAULT_PROMPT_MODEL = "the AI language model"


class MissingKeyError(RuntimeError):
    """The model's API key is not in the environment (the key itself is never read or shown)."""


class _Attack(Protocol):
    model_name: str

    def attack(self, user_task: object, injection_task: object) -> dict[str, str]: ...


@dataclass(slots=True)
class LiveLlm:
    element: CountingLLM | ScriptedLLM
    name: str


def _need_key(provider: str) -> None:
    variable = PROVIDER_KEYS[provider]
    if not os.environ.get(variable):
        raise MissingKeyError(f"{variable} is not set; the {provider} model cannot be called")


def make_model_llm(model: str) -> CountingLLM:
    """A real LLM element. `model` is `groq:<id>`, `openai:<id>`, `anthropic:<id>` or an AgentDojo
    model name (`gpt-4o-2024-05-13`, ...); keys come from GROQ_API_KEY, OPENAI_API_KEY and
    ANTHROPIC_API_KEY, read by the provider's own client."""
    provider, _, ident = model.partition(":")
    llms = import_module("agentdojo.agent_pipeline.agent_pipeline")
    if provider in PROVIDER_KEYS and ident:
        _need_key(provider)
        if provider == "anthropic":
            client = cast(Callable[[], object], attr(import_module("anthropic"), "Anthropic"))()
            build = cast(
                Callable[[object, str], Querying],
                attr(import_module("agentdojo.agent_pipeline.llms.anthropic_llm"), "AnthropicLLM"),
            )
            return CountingLLM(build(client, ident), model)
        openai = import_module("openai")
        make_client = cast(Callable[..., object], attr(openai, "OpenAI"))
        client = (
            make_client(api_key=os.environ["GROQ_API_KEY"], base_url=GROQ_URL)
            if provider == "groq"
            else make_client()
        )
        build = cast(
            Callable[[object, str], Querying],
            attr(import_module("agentdojo.agent_pipeline.llms.openai_llm"), "OpenAILLM"),
        )
        return CountingLLM(build(client, ident), model)
    get_llm = cast(Callable[[str, str, None, str], Querying], attr(llms, "get_llm"))
    providers = cast(
        Mapping[object, str], attr(import_module("agentdojo.models"), "MODEL_PROVIDERS")
    )
    enum = cast(Callable[[str], object], attr(import_module("agentdojo.models"), "ModelsEnum"))
    return CountingLLM(get_llm(providers[enum(model)], model, None, "tool"), model)


def system_message() -> str:
    load = cast(
        Callable[[str | None], str],
        attr(import_module("agentdojo.agent_pipeline.agent_pipeline"), "load_system_message"),
    )
    return load(None)


class _Pipeline(Protocol):
    def query(self, query: str, runtime: object, env: object) -> object: ...


def build_pipeline(llm: object, executor: DispatchExecutor) -> ExecutedOnly:
    """system message, the user query, the LLM, then the tool loop with the lane's executor."""
    agent = import_module("agentdojo.agent_pipeline.agent_pipeline")
    basic = import_module("agentdojo.agent_pipeline.basic_elements")
    loop = import_module("agentdojo.agent_pipeline.tool_execution")
    new_pipeline = cast(Callable[[Sequence[object]], object], attr(agent, "AgentPipeline"))
    new_system = cast(Callable[[str], object], attr(basic, "SystemMessage"))
    new_query = cast(Callable[[], object], attr(basic, "InitQuery"))
    new_loop = cast(Callable[[Sequence[object]], object], attr(loop, "ToolsExecutionLoop"))
    inner = new_pipeline(
        [new_system(system_message()), new_query(), llm, new_loop([executor, llm])]
    )
    return ExecutedOnly(cast(Querying, inner), executor)


def load_attack(name: str, suite: SuiteLike, model: str | None) -> _Attack:
    """The AgentDojo attack, with the victim's name in its text only for a model it knows."""
    registry = import_module("agentdojo.attacks")
    stub = type("Stub", (), {"name": STUB_MODEL})()
    load = cast(Callable[[str, object, object], _Attack], attr(registry, "load_attack"))
    attack = load(name, suite, stub)
    names = cast(Mapping[str, str], attr(import_module("agentdojo.models"), "MODEL_NAMES"))
    attack.model_name = names.get(model or "", DEFAULT_PROMPT_MODEL)
    return attack


def run_live_task(
    suite: SuiteLike,
    attack: _Attack | None,
    snapshot: DojoSnapshot,
    spec: RunSpec,
    config: RunConfig,
    agent: AgentKind,
    model: str | None,
    compile_task: Compile = compile_oracle,
) -> DojoRun:
    """One run through AgentDojo's pipeline and checker."""
    snap_suite = snapshot.suite(spec.suite)
    snap_user = next(t for t in snap_suite.user_tasks if t.task_id == spec.user_task_id)
    snap_injection = next(
        (t for t in snap_suite.injection_tasks if t.task_id == spec.injection_task_id), None
    )
    user_task = suite.user_tasks[spec.user_task_id]
    injection_task = (
        suite.injection_tasks[spec.injection_task_id] if spec.injection_task_id else None
    )
    injections = (
        attack.attack(user_task, injection_task) if attack and injection_task is not None else {}
    )
    compiled: CompiledTask = compile_task(snap_suite, snap_user)

    def factory(execute: Callable[[str, Mapping[str, JsonValue]], ExecResult]) -> Dispatch:
        return make_dispatch(
            spec.lane,
            snap_suite,
            snap_user,
            compiled,
            execute,
            approval=config.approval,
            run_id=spec.key,
        )

    if agent == "scripted":
        hijacked = snap_injection is not None and injection_reaches_agent(spec.lane, snap_injection)
        make_call = cast(
            Callable[..., object],
            attr(import_module("agentdojo.functions_runtime"), "FunctionCall"),
        )
        llm: CountingLLM | ScriptedLLM = ScriptedLLM(
            scripted_calls(snap_user, snap_injection, hijacked=hijacked), make_call
        )
    else:
        if model is None:
            raise ValueError("the model agent needs a model")
        llm = make_model_llm(model)
    executor = DispatchExecutor(factory, output_formatter())
    pipeline = cast(_Pipeline, build_pipeline(llm, executor))
    utility, security = suite.run_task_with_pipeline(
        pipeline, user_task, injection_task, injections
    )
    stats = executor.stats
    return DojoRun.model_validate(
        {
            "suite": spec.suite,
            "lane": spec.lane,
            "user_task_id": spec.user_task_id,
            "injection_task_id": spec.injection_task_id,
            "bucket": compiled.bucket,
            "status": "ok",
            "error": None,
            "utility": utility,
            "attack_succeeded": bool(security) and injection_task is not None,
            "calls": stats.calls,
            "blocked": stats.blocked,
            "escalated": stats.escalated,
            "approved": stats.approved,
            "flagged": stats.flagged,
            "codes": tuple(sorted(stats.codes)),
            "model_calls": llm.model_calls,
        }
    )


def run_all_live(
    snapshot: DojoSnapshot,
    config: RunConfig,
    agent: AgentKind,
    model: str | None,
    *,
    benchmark: str = DEFAULT_BENCHMARK,
    done: Mapping[str, DojoRun] | None = None,
    on_run: Callable[[DojoRun], None] | None = None,
    compile_task: Compile = compile_oracle,
) -> tuple[DojoRun, ...]:
    """All planned runs in AgentDojo; finished runs (by key) are reused, errors are recorded."""
    suites = {name: load_suite(name, benchmark) for name in config.suites}
    attacks: dict[str, _Attack] = {}
    out: list[DojoRun] = []
    for spec in plan_runs(snapshot, config):
        finished = (done or {}).get(spec.key)
        if finished is None:
            try:
                if spec.suite not in attacks:
                    attacks[spec.suite] = load_attack(config.attack, suites[spec.suite], model)
                finished = run_live_task(
                    suites[spec.suite],
                    attacks[spec.suite] if spec.injection_task_id else None,
                    snapshot,
                    spec,
                    config,
                    agent,
                    model,
                    compile_task,
                )
            except MissingKeyError:
                raise
            # Errored run: kept in the log, never counted as utility or as an attack; one failure
            # must not end a long benchmark.
            except Exception as failure:
                finished = failed_run(spec, failure)
            if on_run is not None:
                on_run(finished)
        out.append(finished)
    return tuple(out)
