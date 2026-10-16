import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from notary_cli.main import app
from notary_core.audit import GENESIS_HASH

runner = CliRunner()
EVENTS = Path(__file__).resolve().parents[2] / "world" / "fixtures" / "streams"


def save_a3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["attack", "A3", "--monitor", "fake", "--save-dir", "out"])
    assert result.exit_code == 0
    return tmp_path / "out" / "A3.run.json"


@pytest.mark.invariant("I1")
def test_replay_run_file_verifies_the_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    run_file = save_a3(tmp_path, monkeypatch)
    result = runner.invoke(app, ["replay", "out/A3.run.json"])
    lines = result.output.splitlines()
    assert result.exit_code == 0
    assert lines[0].startswith("run run-A3-notary lane=notary events=")
    assert "run_started" in lines[1]
    assert lines[-1].startswith("chain: OK head=")
    assert " length=" in lines[-1]
    length = len(json.loads(run_file.read_text())["chain"])
    assert lines[-1].endswith(f"length={length}")
    assert f"events={length}" in lines[0]


@pytest.mark.invariant("I1")
def test_replay_detects_a_modified_event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_file = save_a3(tmp_path, monkeypatch)
    data = json.loads(run_file.read_text())
    data["chain"][1]["event"]["run_id"] = "tampered"
    run_file.write_text(json.dumps(data))
    result = runner.invoke(app, ["replay", "out/A3.run.json"])
    assert result.exit_code == 1
    assert "chain: FAILED hash mismatch at index 1" in result.output


@pytest.mark.invariant("I1")
def test_replay_expect_length_detects_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_file = save_a3(tmp_path, monkeypatch)
    data = json.loads(run_file.read_text())
    original = len(data["chain"])
    data["chain"] = data["chain"][:-1]
    run_file.write_text(json.dumps(data))
    assert runner.invoke(app, ["replay", "out/A3.run.json"]).exit_code == 0
    result = runner.invoke(app, ["replay", "out/A3.run.json", "--expect-length", str(original)])
    assert result.exit_code == 1
    assert f"chain: FAILED length mismatch at index {original - 1}" in result.output


@pytest.mark.invariant("I1")
def test_replay_expect_head(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    save_a3(tmp_path, monkeypatch)
    first = runner.invoke(app, ["replay", "out/A3.run.json"])
    head = first.output.splitlines()[-1].split("head=")[1].split()[0]
    assert len(head) == 64
    ok = runner.invoke(app, ["replay", "out/A3.run.json", "--expect-head", head])
    assert ok.exit_code == 0
    wrong = runner.invoke(app, ["replay", "out/A3.run.json", "--expect-head", "f" * 64])
    assert wrong.exit_code == 1
    assert "chain: FAILED head mismatch" in wrong.output
    assert head != GENESIS_HASH


@pytest.mark.invariant("I1")
def test_replay_plain_event_stream_still_works() -> None:
    path = str(EVENTS / "poisoned_bill.notary.json")
    result = runner.invoke(app, ["replay", path])
    assert result.exit_code == 0
    assert "run_started" in result.output
    assert result.output.splitlines()[-1] == "chain: not present (plain event stream)"
    anchored = runner.invoke(app, ["replay", path, "--expect-length", "3"])
    assert anchored.exit_code == 2
    assert "need a run file with an audit chain" in anchored.output


@pytest.mark.invariant("I1")
def test_replay_rejects_garbage(tmp_path: Path) -> None:
    unknown = tmp_path / "unknown.json"
    unknown.write_text('{"type": "nope"}')
    not_json = tmp_path / "garbage.json"
    not_json.write_text("this is not json")
    for path in (unknown, not_json):
        result = runner.invoke(app, ["replay", str(path)])
        assert result.exit_code == 2
        assert "not a run record or event file" in result.output


@pytest.mark.invariant("I6")
def test_bench_stays_a_stub() -> None:
    result = runner.invoke(app, ["bench"])
    assert result.exit_code == 2
    assert "bench: not implemented yet" in result.output


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("command", ["attack", "fuzz", "replay"])
def test_help_documents_exit_codes(command: str) -> None:
    output = runner.invoke(app, [command, "--help"]).output
    assert "exit" in output.lower()
    for code in ("0", "1", "2"):
        assert code in output
