"""CP1: the real monitor passes every fixture and the fuzz harness reports zero violations."""

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from notary_cli.main import app
from notary_world.attacks import KNOWN_REAL_MONITOR_DEVIATIONS
from notary_world.fuzz import run_fuzz

ROOT = Path(__file__).resolve().parents[3]
WORLD_TESTS = ROOT / "packages" / "world" / "tests"
runner = CliRunner()


@pytest.mark.attack("A3")
def test_all_attacks_and_controls_pass_the_real_monitor() -> None:
    result = runner.invoke(app, ["attack", "--all"])
    assert result.exit_code == 0, result.output
    assert "summary: 14 attacks, 4 controls, 0 mismatches" in result.output
    assert dict(KNOWN_REAL_MONITOR_DEVIATIONS) == {}


@pytest.mark.invariant("I1")
@pytest.mark.parametrize("seed", [0, 1, 2])
def test_fuzz_ci_profile_has_zero_violations(seed: int) -> None:
    report = run_fuzz(examples=100, seed=seed, profile="ci")
    assert report.violations == ()
    assert report.ok


@pytest.mark.invariant("I6")
def test_every_invariant_and_attack_has_a_marked_test() -> None:
    text = "\n".join(path.read_text(encoding="utf-8") for path in WORLD_TESTS.glob("*.py"))
    for number in range(1, 7):
        assert f'invariant("I{number}")' in text, f"no test marked I{number}"
    for number in range(1, 15):
        assert f'attack("A{number}")' in text, f"no test marked A{number}"


def _p2_section() -> str:
    phase = (ROOT / "docs" / "phase.md").read_text(encoding="utf-8")
    start = phase.index("## P2 World")
    return phase[start : phase.index("\n## ", start + 1)]


def _coverage_rows() -> dict[str, str]:
    """Row id -> Status cell of the coverage map in docs/threat-model.md."""
    text = (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    section = text.split("### Coverage map", 1)[1].split("\n## ", 1)[0]
    rows: dict[str, str] = {}
    for line in section.splitlines():
        if line.startswith("| ") and not line.startswith(("| ID", "| ---")):
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            rows[cells[0]] = cells[-1]
    return rows


@pytest.mark.attack("A13")
def test_coverage_map_and_phase_doc_are_current() -> None:
    assert "- [ ]" not in _p2_section()
    rows = _coverage_rows()
    for row in ("I1", "I2", "I3", "I4", "I5", "I6", "Oracle (I1-I6 predicates)", "A1-A14"):
        assert not rows[row].startswith("planned"), f"{row}: {rows[row]}"
    phase = (ROOT / "docs" / "phase.md").read_text(encoding="utf-8")
    p2_row = next(line for line in phase.splitlines() if line.startswith("| P2 "))
    assert re.search(r"\|\s*done\s*\|$", p2_row)


@pytest.mark.invariant("I6")
def test_the_cp1_script_is_declared() -> None:
    package = json.loads((ROOT / "packages" / "cli" / "package.json").read_text(encoding="utf-8"))
    assert package["scripts"]["cp1"] == (
        "uv run --no-sync notary attack --all && uv run --no-sync notary fuzz --profile ci"
    )
