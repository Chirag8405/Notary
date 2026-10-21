"""Against the real `agentdojo` package. Skipped in the gate, where it is not installed.

    uv run --no-sync --with agentdojo==0.1.35 pytest packages/eval/tests/test_dojo_agentdojo.py

No model is called: the agent is scripted, the environments and the utility/security checks are
AgentDojo's own.
"""

import pytest

pytest.importorskip("agentdojo")

from notary_eval.dojo_cli import load_snapshot
from notary_eval.dojo_live import build_snapshot
from notary_eval.dojo_live_run import run_all_live
from notary_eval.dojo_run import RunConfig
from notary_eval.dojo_types import SUITES


def test_the_committed_snapshot_is_what_the_installed_package_exports() -> None:
    assert build_snapshot(SUITES, "v1.2.2") == load_snapshot()


def test_scripted_agent_in_agentdojos_own_environment() -> None:
    config = RunConfig(
        suites=("banking", "slack"),
        lanes=("undefended", "notary"),
        max_tasks=3,
        approval="oracle",
    )
    runs = run_all_live(load_snapshot(), config, "scripted", None)
    assert not [r for r in runs if r.status == "error"]
    attacked = [r for r in runs if r.injection_task_id is not None]
    notary = [r for r in attacked if r.lane == "notary"]
    undefended = [r for r in attacked if r.lane == "undefended"]
    assert notary
    assert not any(r.attack_succeeded for r in notary)
    assert sum(r.attack_succeeded for r in undefended) >= 0.9 * len(undefended)
    clean_notary = [r for r in runs if r.lane == "notary" and r.injection_task_id is None]
    assert any(r.utility for r in clean_notary)
