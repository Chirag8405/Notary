import tomllib
from collections.abc import Mapping, Sequence
from functools import cache
from pathlib import Path
from typing import Protocol, cast

import pytest

from notary_core.models import (
    Decision,
    IntentContract,
    LedgerEntry,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
)
from notary_core.monitor import Monitor
from notary_core.policy.sensitive_params import assert_covered
from notary_world.executor import default_monitor
from notary_world.fuzz import (
    MUTANTS,
    FuzzReport,
    fuzz_contract,
    fuzz_scenario,
    fuzz_settings,
    make_machine,
    run_fuzz,
)
from notary_world.tools import (
    TOOL_SPECS,
    default_manifest_hash,
    manifest_infos,
    world_policy,
)


class SettingsView(Protocol):
    """The Hypothesis settings fields these tests read (Hypothesis types them loosely)."""

    max_examples: int
    stateful_step_count: int
    derandomize: bool
    database: object | None
    deadline: object | None


MUTANT_EXAMPLES = 200
RULE_MARKER = "hypothesis_stateful_rule"
WORLD_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def run_mutant(name: str) -> FuzzReport:
    return run_fuzz(examples=MUTANT_EXAMPLES, seed=0, profile="ci", monitor=MUTANTS[name]())


mutant_report = cache(run_mutant)
"""Each mutant is fuzzed once and shared by the tests that inspect its report."""


@pytest.mark.invariant("I1")
def test_real_monitor_has_zero_violations_on_the_ci_profile():
    report = run_fuzz(examples=100, seed=0, profile="ci")
    assert report.violations == ()
    assert report.ok is True
    assert (report.examples, report.seed, report.profile) == (100, 0, "ci")


@pytest.mark.invariant("I2")
@pytest.mark.parametrize("seed", [1, 2, 3])
def test_real_monitor_zero_violations_for_three_seeds(seed: int):
    report = run_fuzz(examples=50, seed=seed, profile="ci")
    assert report.ok is True
    assert report.violations == ()


@pytest.mark.invariant("I2")
def test_allow_all_mutant_is_caught():
    report = mutant_report("allow_all")
    assert report.ok is False
    assert report.violations[0].invariant_id in ("I2", "I3")


@pytest.mark.invariant("I2")
def test_skip_origin_mutant_is_caught():
    report = mutant_report("skip_origin")
    assert report.ok is False
    assert report.violations[0].invariant_id == "I2"


@pytest.mark.invariant("I3")
def test_ignore_readers_mutant_is_caught():
    report = mutant_report("ignore_readers")
    assert report.ok is False
    assert report.violations[0].invariant_id == "I3"


@pytest.mark.invariant("I3")
@pytest.mark.parametrize("name", ["allow_all", "skip_origin", "ignore_readers"])
def test_counterexamples_are_minimized(name: str):
    (violation,) = mutant_report(name).violations
    assert 1 <= len(violation.steps) <= 6
    assert violation.detail


@pytest.mark.invariant("I6")
def test_run_fuzz_is_reproducible():
    first = run_fuzz(examples=30, seed=4, profile="ci")
    second = run_fuzz(examples=30, seed=4, profile="ci")
    assert first.model_dump_json() == second.model_dump_json()
    assert mutant_report("allow_all").model_dump_json() == run_mutant("allow_all").model_dump_json()


def recording_monitor(seen: list[str]) -> Monitor:
    inner = default_monitor()

    def monitor(
        contract: IntentContract,
        proposal: ToolCallProposal,
        values: Mapping[str, ResolvedValue],
        ledger: Sequence[LedgerEntry],
        session: SessionState,
    ) -> Decision:
        seen.append(proposal.tool)
        return inner(contract, proposal, values, ledger, session)

    return monitor


@pytest.mark.invariant("I6")
def test_seed_changes_the_explored_programs():
    first: list[str] = []
    second: list[str] = []
    run_fuzz(examples=20, seed=0, profile="ci", monitor=recording_monitor(first))
    run_fuzz(examples=20, seed=1, profile="ci", monitor=recording_monitor(second))
    assert first
    assert second
    assert first != second


@pytest.mark.invariant("I6")
def test_profile_settings():
    ci = cast(SettingsView, fuzz_settings("ci", 50))
    assert ci.max_examples == 50
    assert ci.stateful_step_count == 15
    assert ci.derandomize is True
    assert ci.database is None
    assert ci.deadline is None
    full = cast(SettingsView, fuzz_settings("full", 50))
    assert full.max_examples == 50
    assert full.stateful_step_count == 30
    assert full.derandomize is False
    assert full.database is None


REQUIRED_RULES = {
    "tool_call",
    "read_secret_then_send",
    "attacker_payment",
    "slack_post",
    "endorse",
    "reject",
    "untrusted_ledger_write",
    "user_ledger_write",
    "contract_update",
    "approval_burst",
}


@pytest.mark.invariant("I5")
def test_machine_declares_the_required_rules():
    machine = make_machine()
    names = {name for name, member in vars(machine).items() if hasattr(member, RULE_MARKER)}
    assert names >= REQUIRED_RULES


@pytest.mark.invariant("I5")
def test_fuzz_contract_is_valid_and_pins_real_manifests():
    contract = fuzz_contract()
    assert IntentContract.model_validate_json(contract.model_dump_json()) == contract
    for scope in contract.allowed_tools:
        assert scope.manifest_hash == default_manifest_hash(scope.tool)
    assert {s.tool for s in contract.allowed_tools} == {s.name for s in TOOL_SPECS}
    assert_covered(world_policy(), manifest_infos())
    assert contract.authorized_irreversible == ("pay_bill", "send_money")
    assert contract.budget.max_approvals == 3


@pytest.mark.invariant("I4")
def test_fuzz_scenario_is_seeded_and_closed():
    scenario = fuzz_scenario()
    assert scenario.calls == ()
    assert [entry.ledger for entry in scenario.ledger] == ["payees", "contacts"]
    assert fuzz_scenario(3).world.seed == 3
    assert fuzz_scenario(3).model_dump_json() == fuzz_scenario(3).model_dump_json()


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("name", ["allow_all", "skip_origin", "ignore_readers"])
def test_mutants_are_valid_monitors(name: str):
    contract = fuzz_contract()
    proposal = ToolCallProposal(
        call_id="c1",
        tool="read_inbox",
        manifest_hash=default_manifest_hash("read_inbox"),
        args={},
    )
    session = SessionState(
        spent_cents=0, effects_used=0, egress_bytes_used=0, approvals_used=0, escalations_used=0
    )
    decision = MUTANTS[name]()(contract, proposal, {}, (), session)
    assert decision.verdict in ("ALLOW", "ESCALATE", "BLOCK")
    if name == "allow_all":
        assert decision.verdict == "ALLOW"
        assert [r.code for r in decision.reasons] == ["STEP_PASS"] * 6


@pytest.mark.invariant("I6")
def test_run_fuzz_validates_arguments():
    with pytest.raises(ValueError, match="examples must be >= 1"):
        run_fuzz(examples=0, seed=0)
    with pytest.raises(ValueError, match="seed must be >= 0"):
        run_fuzz(examples=1, seed=-1)


@pytest.mark.invariant("I6")
def test_monitor_crash_is_not_swallowed():
    def crashing(
        contract: IntentContract,
        proposal: ToolCallProposal,
        values: Mapping[str, ResolvedValue],
        ledger: Sequence[LedgerEntry],
        session: SessionState,
    ) -> Decision:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        run_fuzz(examples=20, seed=0, profile="ci", monitor=crashing)


@pytest.mark.invariant("I6")
def test_hypothesis_is_a_runtime_dependency():
    project = tomllib.loads(WORLD_PYPROJECT.read_text(encoding="utf-8"))["project"]
    assert any(dep.startswith("hypothesis") for dep in project["dependencies"])
