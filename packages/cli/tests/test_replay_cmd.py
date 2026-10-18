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


def write_chain_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """A proxy-style chain (one AuditEntry per line) and its anchor, from the A3 run's chain."""
    run_file = save_a3(tmp_path, monkeypatch)
    chain = json.loads(run_file.read_text())["chain"]
    chain_file = tmp_path / "run.chain.jsonl"
    chain_file.write_text("".join(json.dumps(entry) + "\n" for entry in chain))
    anchor = tmp_path / "run.anchor.json"
    anchor.write_text(json.dumps({"run_id": "r", "length": len(chain), "head": chain[-1]["hash"]}))
    return chain_file, anchor


@pytest.mark.invariant("I1")
def test_replay_verifies_a_chain_file_and_its_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain_file, anchor = write_chain_file(tmp_path, monkeypatch)
    plain = runner.invoke(app, ["replay", str(chain_file)])
    assert plain.exit_code == 0
    lines = plain.output.splitlines()
    assert lines[0].startswith("run run-A3-notary lane=notary events=")
    assert "run_started" in lines[1]
    assert lines[-1].startswith("chain: OK head=")
    anchored = runner.invoke(app, ["replay", str(chain_file), "--anchor", str(anchor)])
    assert anchored.exit_code == 0
    assert anchored.output == plain.output


@pytest.mark.invariant("I1")
def test_replay_detects_an_edited_line_in_a_chain_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain_file, _ = write_chain_file(tmp_path, monkeypatch)
    lines = chain_file.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["event"]["run_id"] = "tampered"
    lines[1] = json.dumps(entry)
    chain_file.write_text("\n".join(lines) + "\n")
    result = runner.invoke(app, ["replay", str(chain_file)])
    assert result.exit_code == 1
    assert "chain: FAILED hash mismatch at index 1" in result.output


@pytest.mark.invariant("I1")
def test_replay_detects_a_deleted_line_in_the_middle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain_file, _ = write_chain_file(tmp_path, monkeypatch)
    lines = chain_file.read_text().splitlines()
    del lines[1]
    chain_file.write_text("\n".join(lines) + "\n")
    result = runner.invoke(app, ["replay", str(chain_file)])
    assert result.exit_code == 1
    assert "chain: FAILED index mismatch at index 1" in result.output


@pytest.mark.invariant("I1")
def test_replay_anchor_detects_a_truncated_chain_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain_file, anchor = write_chain_file(tmp_path, monkeypatch)
    lines = chain_file.read_text().splitlines()
    chain_file.write_text("\n".join(lines[:-1]) + "\n")
    assert runner.invoke(app, ["replay", str(chain_file)]).exit_code == 0  # the chain alone cannot
    result = runner.invoke(app, ["replay", str(chain_file), "--anchor", str(anchor)])
    assert result.exit_code == 1
    assert "chain: FAILED length mismatch" in result.output


@pytest.mark.invariant("I1")
def test_replay_reports_a_partial_last_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain_file, _ = write_chain_file(tmp_path, monkeypatch)
    text = chain_file.read_text()
    count = len(text.splitlines())
    chain_file.write_text(text + '{"index": 99, "prev_ha')
    result = runner.invoke(app, ["replay", str(chain_file)])
    assert result.exit_code == 1
    assert f"chain: FAILED unreadable entry at index {count}" in result.output


def test_replay_anchor_input_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    chain_file, anchor = write_chain_file(tmp_path, monkeypatch)
    both = runner.invoke(
        app, ["replay", str(chain_file), "--anchor", str(anchor), "--expect-length", "1"]
    )
    assert both.exit_code == 2
    bad = tmp_path / "bad.json"
    bad.write_text('{"length": "x", "head": null}')
    assert runner.invoke(app, ["replay", str(chain_file), "--anchor", str(bad)]).exit_code == 2
    plain = str(EVENTS / "poisoned_bill.notary.json")
    on_plain = runner.invoke(app, ["replay", plain, "--anchor", str(anchor)])
    assert on_plain.exit_code == 2
    assert "--anchor need a run file with an audit chain" in on_plain.output


def test_bench_out_writes_one_results_file_per_lane(tmp_path: Path) -> None:
    result = runner.invoke(app, ["bench", "--out", str(tmp_path)])
    assert result.exit_code == 0
    assert sorted(f.name for f in tmp_path.iterdir()) == ["none.json", "notary.json"]


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("command", ["attack", "fuzz", "replay"])
def test_help_documents_exit_codes(command: str) -> None:
    output = runner.invoke(app, [command, "--help"]).output
    assert "exit" in output.lower()
    for code in ("0", "1", "2"):
        assert code in output
