"""The external attack library (X: published sets, Y: second author), issue #306."""

import re
from datetime import date
from pathlib import Path

import pytest

from notary_core.models import ExpectedOutcome
from notary_world.attacks import ALL_ATTACKS
from notary_world.executor import default_monitor
from notary_world.external import (
    ALL_EXTERNAL,
    EXTERNAL_SCENARIO_IDS,
    ExternalAttack,
    ExternalNotFoundError,
    external_scenario,
    get_external,
    run_external,
    with_optional_params,
)
from notary_world.loader import FIXTURES_DIR
from notary_world.oracle import goal_spec
from notary_world.scenarios import bill_contract

THREAT_MODEL = Path(__file__).resolve().parents[3] / "docs" / "threat-model.md"
PUBLISHED_LICENCES = ("MIT", "CC BY-SA 4.0")
BLIND_LIMIT = 28
"""Y1..Y28 are blind predictions; Y29 and Y30 are follow-ups written after seeing results."""


def test_the_ids_are_stable_and_the_cp1_library_is_untouched() -> None:
    xs = [a.attack_id for a in ALL_EXTERNAL if a.attack_id[0] == "X"]
    ys = [a.attack_id for a in ALL_EXTERNAL if a.attack_id[0] == "Y"]
    assert xs == [f"X{i}" for i in range(1, len(xs) + 1)]
    assert ys == [f"Y{i}" for i in range(1, len(ys) + 1)]
    assert len(xs) >= 28
    assert len(ys) >= 30
    assert [f.case.id for f in ALL_ATTACKS] == [f"A{i}" for i in range(1, 15)]
    files = sorted(p.stem for p in (FIXTURES_DIR / "external").glob("*.json"))
    assert files == sorted([*xs, *ys])
    with pytest.raises(ExternalNotFoundError):
        get_external("X99")


def test_every_published_fixture_records_source_licence_date_and_wording() -> None:
    for attack in ALL_EXTERNAL:
        prov = attack.provenance
        assert all((prov.source, prov.url, prov.note)), attack.attack_id
        date.fromisoformat(prov.retrieved)
        if attack.series == "second_author":
            assert attack.attack_id.startswith("Y")
            assert prov.wording == "authored"
            assert "threat-model.md" in prov.source
        else:
            assert attack.attack_id.startswith("X")
            assert prov.url.startswith("https://"), attack.attack_id
            assert any(prov.licence.startswith(name) for name in PUBLISHED_LICENCES), (
                attack.attack_id
            )
    series = {a.series for a in ALL_EXTERNAL}
    assert series == {"agentdojo", "injecagent", "greshake", "owasp", "second_author"}


def test_second_author_predictions_are_committed_and_the_follow_ups_are_marked() -> None:
    for attack in ALL_EXTERNAL:
        if attack.series == "second_author":
            assert isinstance(attack.predicted, ExpectedOutcome)
            number = int(attack.attack_id[1:])
            assert attack.informed == (number > BLIND_LIMIT), attack.attack_id
        else:
            assert attack.predicted is None
            assert not attack.informed


def test_goals_are_in_the_oracle_catalog_and_tools_exist_in_the_world() -> None:
    from notary_world.tools import get_tool

    for attack in ALL_EXTERNAL:
        assert goal_spec(attack.attacker_goal_id).side == "attacker"
        assert goal_spec(attack.user_goal_id).side == "user"
        assert len(attack.scripted) >= 1
        for call in attack.scripted:
            assert get_tool(call.tool) is not None, call.call_id


@pytest.mark.parametrize("attack", ALL_EXTERNAL, ids=lambda a: a.attack_id)
def test_every_external_attack_has_its_pinned_outcomes_and_no_undeclared_effect(
    attack: ExternalAttack,
) -> None:
    result, record = run_external(attack.attack_id)
    mismatched = [c.call_id for c in result.checks if not c.matches]
    assert mismatched == []
    assert result.invariants_ok
    assert record.halted is None
    if result.goal_reached:
        assert attack.residual is not None, (
            "the attacker goal was reached without a declared residual"
        )
    if attack.residual is not None and attack.residual.kind == "known_gap":
        assert attack.residual.issue is not None


def test_an_undefended_attack_is_declared_and_each_gap_names_its_issue() -> None:
    declared = {a.attack_id: a.residual for a in ALL_EXTERNAL if a.residual is not None}
    assert {"Y2", "Y3", "Y13", "Y27", "Y28", "X22"} <= set(declared)
    gaps = {k: r.issue for k, r in declared.items() if r.kind == "known_gap"}
    assert gaps == {"Y13": 341, "Y27": 342}
    for attack in ALL_EXTERNAL:
        if attack.attack_id in declared:
            continue
        result, _ = run_external(attack.attack_id)
        assert not result.goal_reached, attack.attack_id


def test_the_runs_are_deterministic() -> None:
    first = run_external("Y3")[0]
    assert run_external("Y3")[0] == first
    assert run_external("X4", monitor=default_monitor())[0] == run_external("X4")[0]


def test_external_scenarios_build_with_pinned_tools() -> None:
    for scenario_id in EXTERNAL_SCENARIO_IDS:
        scenario = external_scenario(scenario_id)
        assert scenario.scenario_id == scenario_id
        assert scenario.contract.allowed_tools
    with pytest.raises(ValueError, match="unknown scenario"):
        external_scenario("no_such_scenario")


def test_optional_params_are_added_at_the_floor_and_never_replace_a_marker() -> None:
    base = bill_contract()
    widened = with_optional_params(base)
    pay_base = next(s for s in base.allowed_tools if s.tool == "pay_bill")
    pay_wide = next(s for s in widened.allowed_tools if s.tool == "pay_bill")
    assert "reference" not in pay_base.params
    assert "reference" in pay_wide.params
    assert pay_wide.params["reference"].kind == "free"
    assert {k: v for k, v in pay_wide.params.items() if k in pay_base.params} == pay_base.params
    assert widened.budget.max_egress_bytes >= 100


def test_the_results_table_in_the_threat_model_lists_every_external_attack() -> None:
    text = THREAT_MODEL.read_text(encoding="utf-8")
    section = text.split("### External attack library", 1)[1].split("\n## ", 1)[0]
    rows = set(re.findall(r"^\| ([XY]\d+) ", section, re.M))
    assert rows == {a.attack_id for a in ALL_EXTERNAL}
