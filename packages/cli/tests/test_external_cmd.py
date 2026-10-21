"""`notary attack --external`: the external library, kept apart from the CP1 contract."""

import json

from typer.testing import CliRunner

from notary_cli.main import app
from notary_world.external import ALL_EXTERNAL

runner = CliRunner()


def test_the_whole_library_passes_and_prints_one_summary_line() -> None:
    result = runner.invoke(app, ["attack", "--external"])
    assert result.exit_code == 0, result.output
    summary = result.output.strip().splitlines()[-1]
    assert summary.startswith(f"summary: {len(ALL_EXTERNAL)} external attacks (28 from published")
    assert "mismatches 0" in summary
    for attack in ALL_EXTERNAL:
        assert f"\n{attack.attack_id} " in result.output


def test_one_attack_shows_provenance_prediction_and_residual() -> None:
    result = runner.invoke(app, ["attack", "Y13"])
    assert result.exit_code == 0, result.output
    assert "predicted (before the first run): ALLOW/-/LEDGER_EXACT_MATCH" in result.output
    assert "residual: known_gap #341" in result.output
    published = runner.invoke(app, ["attack", "X1"])
    assert "MIT" in published.output
    assert "adapted" in published.output


def test_cp1_is_unchanged_and_the_external_flag_is_not_part_of_all() -> None:
    cp1 = runner.invoke(app, ["attack", "--all"])
    assert "summary: 14 attacks, 4 controls, 0 mismatches" in cp1.output
    assert runner.invoke(app, ["attack", "--external", "--all"]).exit_code == 2
    assert runner.invoke(app, ["attack", "--external", "--monitor", "fake"]).exit_code == 2


def test_listing_json_and_unknown_ids() -> None:
    listing = runner.invoke(app, ["attack", "--external", "--list"])
    assert len(listing.output.strip().splitlines()) == len(ALL_EXTERNAL)
    as_json = runner.invoke(app, ["attack", "Y1", "--json"])
    (entry,) = json.loads(as_json.output)
    assert entry["attack_id"] == "Y1"
    assert runner.invoke(app, ["attack", "X99"]).exit_code == 2
    assert runner.invoke(app, ["attack", "X1", "--external"]).exit_code == 2
