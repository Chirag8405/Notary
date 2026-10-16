"""Result shapes and JSON export for charts. Harness not implemented yet."""

from pathlib import Path
from typing import Annotated

from pydantic import Field

from notary_core.models import NotaryModel


class TaskResult(NotaryModel):
    suite: str
    task_id: str
    utility: bool
    attack_succeeded: bool


class EvalResults(NotaryModel):
    defence: str
    results: tuple[TaskResult, ...]
    seed: Annotated[int, Field(ge=0)]


def export_results(results: EvalResults, path: Path) -> None:
    """Write results as pretty JSON for the chart tooling."""
    path.write_text(results.model_dump_json(indent=2) + "\n", encoding="utf-8")


def run_agentdojo(defence: str, seed: int) -> EvalResults:
    """Run the AgentDojo suites against a defence. Not implemented yet."""
    raise NotImplementedError
