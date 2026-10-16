"""AgentRunner interface (frozen contract). Implementations live in `apps/server`.

Lanes are configurations of ONE runner with two hook points:
  - Undefended      = no hooks
  - Classifier-only = a pre-filter on tool results (lane B supplies `ClassifierFilter`)
  - NOTARY          = Gateway + monitor gate
"""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol

from notary_core.gateway import ToolResult
from notary_core.models import Event, Lane, NotaryModel
from notary_core.monitor import Monitor


class FilterFlag(NotaryModel):
    """A span a classifier flagged. Advisory only: it never decides an effect."""

    field: str
    start: int
    end: int
    label: str


class FilteredResult(NotaryModel):
    result: ToolResult
    flags: tuple[FilterFlag, ...]


class ResultPreFilter(Protocol):
    """Hook (a): applied to tool results before the agent sees them. Pure."""

    def __call__(self, result: ToolResult) -> FilteredResult: ...


@dataclass(frozen=True, slots=True)
class RunnerHooks:
    pre_filter: ResultPreFilter | None
    gate: Monitor | None
    """Hook (b): the Gateway/monitor gate."""


def hooks_for_lane(
    lane: Lane,
    *,
    classifier_filter: ResultPreFilter | None = None,
    gate: Monitor | None = None,
) -> RunnerHooks:
    """Build the hooks a lane is allowed to have; raise `ValueError` for any other combination."""
    if lane == "undefended":
        if classifier_filter is not None or gate is not None:
            raise ValueError("the undefended lane has no hooks")
        return RunnerHooks(pre_filter=None, gate=None)
    if lane == "classifier":
        if classifier_filter is None or gate is not None:
            raise ValueError("the classifier lane needs a pre-filter and no gate")
        return RunnerHooks(pre_filter=classifier_filter, gate=None)
    if gate is None or classifier_filter is not None:
        raise ValueError("the notary lane needs a gate and no classifier pre-filter")
    return RunnerHooks(pre_filter=None, gate=gate)


class AgentRunner(Protocol):
    def run(
        self, *, lane: Lane, scenario: str, run_id: str, hooks: RunnerHooks
    ) -> Iterator[Event]: ...
