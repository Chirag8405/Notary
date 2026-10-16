import json
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from typer.testing import CliRunner

from notary_cli.main import app
from notary_cli.reports import AttackReport
from notary_core.models import CHECK_ORDER
from notary_world.attacks import ALL_ATTACKS, ALL_CONTROLS, KNOWN_REAL_MONITOR_DEVIATIONS
from notary_world.executor import RunRecord

runner = CliRunner()
INVARIANTS_OK = "invariants: I1:ok I2:ok I3:ok I4:ok I5:ok I6:ok"


def attack(*args: str) -> tuple[int, str]:
    result = runner.invoke(app, ["attack", *args])
    return result.exit_code, result.output


@pytest.mark.attack("A1")
def test_attack_list_prints_fourteen_tab_separated_lines() -> None:
    code, output = attack("--list")
    lines = output.splitlines()
    assert code == 0
    assert output.endswith("\n")
    assert output.count("\n") == 14
    assert len(lines) == 14
    assert lines[2] == "A3\tData-only poisoning\tESCALATE\tcorroboration"
    assert lines[12].startswith("A13\tText-to-text deception\tALLOW\toutput_guard")
    assert all(line.count("\t") == 3 for line in lines)


@pytest.mark.attack("A1")
def test_attack_a1_real_monitor_text_output() -> None:
    code, output = attack("A1")
    assert code == 0
    assert "A1 Instruction override (monitor=real)" in output
    assert (
        "A1.c1 send_email expected BLOCK/scope/SCOPE_TOOL_NOT_IN_CONTRACT "
        "actual BLOCK/scope/SCOPE_TOOL_NOT_IN_CONTRACT OK"
    ) in output
    assert INVARIANTS_OK in output
    assert output.endswith("result: OK\n")


@pytest.mark.attack("A3")
def test_attack_a3_real_monitor_reports_the_known_deviation() -> None:
    code, output = attack("A3")
    assert code == (1 if "A3.c1" in KNOWN_REAL_MONITOR_DEVIATIONS else 0)
    if code == 1:
        assert "MISMATCH (known deviation:" in output
        assert output.endswith("result: MISMATCH\n")


@pytest.mark.attack("A3")
def test_attack_a3_fake_monitor_matches() -> None:
    code, output = attack("A3", "--monitor", "fake")
    assert code == 0
    assert "A3 Data-only poisoning (monitor=fake)" in output
    assert (
        "A3.c1 pay_bill expected ESCALATE/corroboration/LEDGER_NOVEL_ESCALATE "
        "actual ESCALATE/corroboration/LEDGER_NOVEL_ESCALATE OK"
    ) in output
    assert output.endswith("result: OK\n")


@pytest.mark.attack("A14")
def test_attack_id_is_case_insensitive_and_accepts_controls() -> None:
    assert attack("a1") == attack("A1")
    code, output = attack("B1")
    assert code == 0
    assert output.endswith("result: OK\n")


@pytest.mark.attack("A1")
def test_unknown_attack_id_is_a_usage_error() -> None:
    code, output = attack("Z9")
    assert code == 2
    assert "unknown attack id: Z9" in output


@pytest.mark.attack("A1")
def test_attack_without_selector_is_a_usage_error() -> None:
    code, output = attack()
    assert code == 2
    assert "give an attack id, --list or --all" in output
    code, output = attack("A1", "--all")
    assert code == 2
    assert "give an attack id, --list or --all" in output


@pytest.mark.attack("A3")
def test_attack_json_roundtrips() -> None:
    code, output = attack("A3", "--json", "--monitor", "fake")
    report = AttackReport.model_validate_json(output)
    assert code == 0
    assert report.ok is True
    assert report.monitor == "fake"
    assert report.checks[1].call_id == "A3.c1"
    assert output == report.model_dump_json(indent=2) + "\n"


@pytest.mark.attack("A13")
def test_attack_a13_is_reported_as_deferred() -> None:
    code, output = attack("A13", "--monitor", "fake")
    assert code == 0
    assert "attacker goal deferred; user goal deferred" in output


@pytest.mark.invariant("I1")
def test_attack_save_dir_writes_run_and_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    code, output = attack("A3", "--monitor", "fake", "--save-dir", "out")
    assert code == 0
    assert "saved out/A3.run.json\n" in output
    assert "saved out/A3.report.json\n" in output
    record = RunRecord.model_validate_json((tmp_path / "out" / "A3.run.json").read_text())
    report = AttackReport.model_validate_json((tmp_path / "out" / "A3.report.json").read_text())
    assert record.run_id == "run-A3-notary"
    assert report.attack_id == "A3"
    assert (tmp_path / "out" / "A3.run.json").read_text().endswith("}\n")


@pytest.mark.attack("A14")
def test_attack_all_with_fake_monitor_is_green() -> None:
    code, output = attack("--all", "--monitor", "fake")
    lines = output.splitlines()
    assert code == 0
    assert lines[-1] == "summary: 14 attacks, 4 controls, 0 mismatches"
    assert len(lines) - 2 == 18
    assert lines[0].split() == ["ID", "NAME", "VERDICT", "STEP", "RESULT"]
    assert any(line.startswith("A13 ") and "OK (deferred)" in line for line in lines)
    name_column = lines[0].index("NAME")
    assert all(line[name_column - 1] == " " for line in lines[1:-1])
    assert lines[0].index("VERDICT") > name_column


@pytest.mark.attack("A14")
def test_attack_all_with_real_monitor_matches_the_known_deviation_list() -> None:
    code, output = attack("--all")
    deviating = {
        fixture.case.id
        for fixture in ALL_ATTACKS
        if any(call.call_id in KNOWN_REAL_MONITOR_DEVIATIONS for call in fixture.scripted)
    } | {
        control.control_id
        for control in ALL_CONTROLS
        if any(call.call_id in KNOWN_REAL_MONITOR_DEVIATIONS for call in control.scripted)
    }
    assert code == (1 if deviating else 0)
    assert output.splitlines()[-1] == (
        f"summary: 14 attacks, 4 controls, {len(deviating)} mismatches"
    )


@pytest.mark.attack("A14")
def test_attack_all_json_is_an_array_of_reports() -> None:
    code, output = attack("--all", "--json", "--monitor", "fake")
    reports = TypeAdapter(list[AttackReport]).validate_json(output)
    assert isinstance(json.loads(output), list)
    assert code == 0
    assert [r.attack_id for r in reports] == [f"A{i}" for i in range(1, 15)] + [
        f"B{i}" for i in range(1, 5)
    ]


@pytest.mark.invariant("I6")
def test_attack_output_is_deterministic_and_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    first = attack("A3", "--monitor", "fake", "--save-dir", "out")
    second = attack("A3", "--monitor", "fake", "--save-dir", "out")
    assert first == second
    assert str(tmp_path) not in first[1]
    assert "/tmp" not in first[1]


@pytest.mark.attack("A1")
def test_deciding_steps_in_the_list_are_known() -> None:
    steps = {line.split("\t")[3] for line in attack("--list")[1].splitlines()}
    assert steps <= {*CHECK_ORDER, "none", "output_guard"}
