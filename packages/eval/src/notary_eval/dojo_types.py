"""Shapes of the AgentDojo harness: the task snapshot, one run, the cells and the report.

AgentDojo (https://github.com/ethz-spylab/agentdojo, MIT licence, `agentdojo==0.1.35`) is untyped
and heavy, so the harness never imports it at module level. Everything it needs from a suite is
copied into a `DojoSnapshot` (tools, prompts, ground-truth calls, injection goals); the adapter in
`notary_eval.dojo_live` is the only code that touches the real package.
"""

from typing import Annotated, Literal

from pydantic import Field, JsonValue

from notary_core.models import DecisionUnit, Lane, NotaryModel
from notary_eval.mcp_eval import Rate
from notary_eval.results import EvalResults

SNAPSHOT_FORMAT = 1
SUITES: tuple[str, ...] = ("banking", "slack")
"""The suites the tool table (`dojo_tools`) covers; workspace and travel are not mapped yet."""
LANES: tuple[Lane, ...] = ("undefended", "classifier", "notary")
Bucket = Literal["fully_specified", "parameter_open", "action_open", "read_only"]
BUCKETS: tuple[Bucket, ...] = ("fully_specified", "parameter_open", "action_open", "read_only")
"""The three buckets of the threat model's Metrics, plus tasks with no effect at all."""
ApprovalPolicy = Literal["reject", "oracle"]
"""What the simulated user answers to an ESCALATE: refuse always, or approve what the task needs."""
AgentKind = Literal["scripted", "model"]
SourceKind = Literal["snapshot", "agentdojo"]
RunStatus = Literal["ok", "error"]
ALL = "all"
"""The `suite` or `bucket` of a cell that pools every suite or bucket."""


class DojoParam(NotaryModel):
    name: str
    types: tuple[str, ...]
    """JSON schema types the parameter accepts (`integer`, `string`, `null`, ...)."""


class DojoTool(NotaryModel):
    name: str
    description: str
    input_schema: str
    """Canonical JSON text of the tool's input schema (hashed into the pinned manifest)."""
    params: tuple[DojoParam, ...]


class DojoCall(NotaryModel):
    function: str
    args: dict[str, JsonValue]
    output: str | None
    """What the tool printed on the clean environment (as the model sees it), when known."""


class DojoUserTask(NotaryModel):
    task_id: str
    prompt: str
    calls: tuple[DojoCall, ...]
    """The ground-truth tool calls that solve the task."""


class DojoInjectionTask(NotaryModel):
    task_id: str
    goal: str
    injection_text: str
    """The `important_instructions` text an attacker plants in the content for this goal."""
    calls: tuple[DojoCall, ...]
    """The ground-truth tool calls that reach the attacker's goal."""


class DojoLedgerSeed(NotaryModel):
    """A value of the user's own state (a past payee, a workspace member) that the ledger trusts."""

    ledger: str
    key: str
    value: str
    unit: DecisionUnit


class DojoSuite(NotaryModel):
    suite: str
    tools: tuple[DojoTool, ...]
    user_tasks: tuple[DojoUserTask, ...]
    injection_tasks: tuple[DojoInjectionTask, ...]
    ledger: tuple[DojoLedgerSeed, ...]


class DojoSnapshot(NotaryModel):
    format: Annotated[int, Field(ge=1)]
    benchmark: str
    """Benchmark version, e.g. `v1.2.2`."""
    agentdojo_version: str
    licence: str
    suites: tuple[DojoSuite, ...]

    def suite(self, name: str) -> DojoSuite:
        for suite in self.suites:
            if suite.suite == name:
                return suite
        raise KeyError(f"suite {name!r} is not in the snapshot")


class DojoRun(NotaryModel):
    """One task run in one lane: a user task alone, or a user task under one injection task."""

    suite: str
    lane: Lane
    user_task_id: str
    injection_task_id: str | None
    bucket: Bucket
    status: RunStatus
    error: str | None
    utility: bool
    attack_succeeded: bool
    calls: Annotated[int, Field(ge=0)]
    """Tool calls the agent proposed."""
    blocked: Annotated[int, Field(ge=0)]
    escalated: Annotated[int, Field(ge=0)]
    approved: Annotated[int, Field(ge=0)]
    flagged: Annotated[int, Field(ge=0)]
    """Tool results the classifier stand-in redacted."""
    codes: tuple[str, ...]
    """Distinct reason codes of the failing checks, sorted."""
    model_calls: Annotated[int, Field(ge=0)]

    @property
    def key(self) -> str:
        return run_key(self.suite, self.lane, self.user_task_id, self.injection_task_id)


def run_key(suite: str, lane: str, user_task_id: str, injection_task_id: str | None) -> str:
    return "|".join((suite, lane, user_task_id, injection_task_id or "-"))


class DojoMeta(NotaryModel):
    label: str
    sample: bool
    """True for the committed fixture: a scripted agent, not a model; never quote it as a result."""
    date: str
    agent: AgentKind
    model: str | None
    source: SourceKind
    benchmark: str
    agentdojo_version: str
    attack: str
    approval: ApprovalPolicy
    compiler: str
    rounds: Annotated[int, Field(ge=1)]
    suites: tuple[str, ...]
    lanes: tuple[Lane, ...]
    max_tasks: int | None
    planned_runs: Annotated[int, Field(ge=0)]
    model_calls: Annotated[int, Field(ge=0)]
    notes: tuple[str, ...]


class DojoCell(NotaryModel):
    """The three headline metrics of one lane over one suite (or all) and one bucket (or all)."""

    suite: str
    lane: Lane
    bucket: str
    utility_clean: Rate
    """User tasks solved with no attack."""
    utility_attack: Rate
    """User tasks solved while under attack (one run per user and injection task)."""
    asr: Rate
    """Runs in which the attacker's goal was reached."""
    escalation: Rate
    """Clean runs in which the monitor escalated at least one call."""
    errored: Annotated[int, Field(ge=0)]


class AgentDojoReport(NotaryModel):
    meta: DojoMeta
    runs: tuple[DojoRun, ...]
    evals: tuple[EvalResults, ...]
    """The same runs as `EvalResults`, one per lane (the shape `notary bench` exports)."""
    cells: tuple[DojoCell, ...]
