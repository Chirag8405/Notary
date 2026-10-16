from pathlib import Path

import pytest

from notary_eval import EvalResults, TaskResult, export_results
from notary_eval.results import run_agentdojo


def test_export_round_trip(tmp_path: Path) -> None:
    results = EvalResults(
        defence="notary",
        seed=1,
        results=(TaskResult(suite="banking", task_id="t1", utility=True, attack_succeeded=False),),
    )
    out = tmp_path / "r.json"
    export_results(results, out)
    assert EvalResults.model_validate_json(out.read_text()) == results


def test_harness_stub() -> None:
    with pytest.raises(NotImplementedError):
        run_agentdojo("notary", 0)
