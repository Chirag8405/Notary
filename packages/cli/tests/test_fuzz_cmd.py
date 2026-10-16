import pytest
from typer.testing import CliRunner

from notary_cli.main import app
from notary_core.monitor import Monitor
from notary_world.fuzz import MUTANTS, FuzzProfile, FuzzReport, FuzzViolation, run_fuzz

runner = CliRunner()


@pytest.mark.invariant("I1")
def test_fuzz_defaults_and_ok_output() -> None:
    result = runner.invoke(app, ["fuzz", "--examples", "5"])
    assert result.exit_code == 0
    assert result.output == "fuzz: profile=ci examples=5 seed=0\nviolations: 0\nresult: OK\n"


@pytest.mark.invariant("I3")
def test_fuzz_violation_prints_the_minimized_program_and_exits_1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake(
        *, examples: int, seed: int, profile: FuzzProfile = "ci", monitor: Monitor | None = None
    ) -> FuzzReport:
        violation = FuzzViolation(
            invariant_id="I3",
            detail="I3 violated: x",
            steps=("propose f1 read_file {...}", "propose f2 send_email {...}"),
        )
        return FuzzReport(
            examples=examples, seed=seed, profile=profile, violations=(violation,), ok=False
        )

    monkeypatch.setattr("notary_cli.main.run_fuzz", fake)
    result = runner.invoke(app, ["fuzz", "--examples", "7", "--seed", "3", "--profile", "full"])
    assert result.exit_code == 1
    assert "fuzz: profile=full examples=7 seed=3" in result.output
    assert "violations: 1" in result.output
    assert "VIOLATION I3: I3 violated: x" in result.output
    assert "  minimized program (2 steps):" in result.output
    assert "    1. propose f1" in result.output
    assert "    2. propose f2" in result.output
    assert result.output.endswith("result: VIOLATION\n")


@pytest.mark.invariant("I2")
def test_fuzz_real_run_with_a_mutant_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    def with_mutant(
        *, examples: int, seed: int, profile: FuzzProfile = "ci", monitor: Monitor | None = None
    ) -> FuzzReport:
        return run_fuzz(examples=200, seed=seed, profile=profile, monitor=MUTANTS["allow_all"]())

    monkeypatch.setattr("notary_cli.main.run_fuzz", with_mutant)
    result = runner.invoke(app, ["fuzz"])
    assert result.exit_code == 1
    assert "violations: 1" in result.output
    assert "result: VIOLATION" in result.output


@pytest.mark.invariant("I6")
@pytest.mark.parametrize(
    "options",
    [["--examples", "0"], ["--seed", "-1"], ["--profile", "nope"]],
)
def test_fuzz_rejects_bad_options(options: list[str]) -> None:
    assert runner.invoke(app, ["fuzz", *options]).exit_code == 2


@pytest.mark.invariant("I6")
def test_fuzz_output_is_deterministic() -> None:
    first = runner.invoke(app, ["fuzz", "--examples", "5", "--seed", "2"])
    second = runner.invoke(app, ["fuzz", "--examples", "5", "--seed", "2"])
    assert first.output == second.output
