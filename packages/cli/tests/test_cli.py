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


def test_bench_is_stubbed() -> None:
    assert runner.invoke(app, ["bench"]).exit_code == 2


def test_attack_list() -> None:
    result = runner.invoke(app, ["attack", "--list"])
    assert result.exit_code == 0
    assert result.output.count("\n") == 14
    assert result.output.splitlines()[0].startswith("A1\t")
