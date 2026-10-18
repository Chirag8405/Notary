from pathlib import Path

from typer.testing import CliRunner

from notary_cli.main import app

runner = CliRunner()
EVENTS = Path(__file__).resolve().parents[2] / "world" / "fixtures" / "streams"


def test_replay_prints_typed_events() -> None:
    result = runner.invoke(app, ["replay", str(EVENTS / "poisoned_bill.notary.json")])
    assert result.exit_code == 0
    assert "run_started" in result.output


def test_replay_rejects_invalid_event(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"type": "nope"}')
    assert runner.invoke(app, ["replay", str(bad)]).exit_code != 0


def test_bench_runs_both_lanes() -> None:
    result = runner.invoke(app, ["bench"])
    assert result.exit_code == 0
    lines = result.output.strip().splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("none")
    assert "attacks succeeded 0/14" not in lines[0]
    assert lines[1].startswith("notary")
    assert "attacks succeeded 0/14" in lines[1]
    assert "controls completed 4/4" in lines[1]


def test_attack_list() -> None:
    result = runner.invoke(app, ["attack", "--list"])
    assert result.exit_code == 0
    assert result.output.count("\n") == 14
    assert result.output.splitlines()[0].startswith("A1\t")
