from pathlib import Path

import notary_eval.results as results_module
from notary_eval import EvalResults, TaskResult, export_results


def test_export_round_trip(tmp_path: Path) -> None:
    results = EvalResults(
        defence="notary",
        seed=1,
        results=(TaskResult(suite="banking", task_id="t1", utility=True, attack_succeeded=False),),
    )
    out = tmp_path / "r.json"
    export_results(results, out)
    assert EvalResults.model_validate_json(out.read_text()) == results


def test_the_agentdojo_stub_is_gone() -> None:
    assert not hasattr(results_module, "run_agentdojo")
    assert "NotImplementedError" not in Path(results_module.__file__).read_text(encoding="utf-8")


def test_a_result_file_written_before_the_agentdojo_harness_still_loads() -> None:
    old = (
        '{"defence":"none","results":[{"suite":"library","task_id":"A1",'
        '"utility":true,"attack_succeeded":true}],"seed":0}'
    )
    loaded = EvalResults.model_validate_json(old)
    assert loaded.results[0].task_id == "A1"
