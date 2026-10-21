"""Result shapes and JSON export for charts.

The AgentDojo harness (`notary_eval.dojo_run`, `run_agentdojo`) exports a richer report
(`AgentDojoReport`) that also carries these shapes, one `EvalResults` per lane.
"""

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
