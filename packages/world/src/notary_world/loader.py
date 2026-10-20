"""Typed loaders for the JSON fixtures shipped in packages/world/fixtures."""

from pathlib import Path

from pydantic import TypeAdapter

from notary_core.models import AttackCase, Event
from notary_world.models import AttackFixture, Cassette, World

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"

_EVENTS = TypeAdapter(tuple[Event, ...])


def load_world(path: Path | None = None) -> World:
    target = path or FIXTURES_DIR / "world.json"
    return World.model_validate_json(target.read_text(encoding="utf-8"))


def load_attack_fixtures(directory: Path | None = None) -> tuple[AttackFixture, ...]:
    """All attack fixtures, ordered A1..A14 (one JSON file per attack)."""
    root = directory or FIXTURES_DIR / "attacks"
    fixtures = [
        AttackFixture.model_validate_json(path.read_text(encoding="utf-8"))
        for path in root.glob("A*.json")
    ]
    return tuple(sorted(fixtures, key=lambda f: int(f.case.id[1:])))


def load_attacks(directory: Path | None = None) -> tuple[AttackCase, ...]:
    return tuple(f.case for f in load_attack_fixtures(directory))


CASSETTES_DIR = FIXTURES_DIR / "cassettes"
"""The committed (scripted) cassette set."""
REAL_CASSETTES_DIR = FIXTURES_DIR / "cassettes-real"
"""Where a real-model cassette set goes once the owner records and commits it (#308)."""


def load_cassette(name: str, directory: Path | None = None) -> Cassette:
    """`<directory>/<name>.json`; the committed scripted set when no directory is given."""
    target = (directory or CASSETTES_DIR) / f"{name}.json"
    return Cassette.model_validate_json(target.read_text(encoding="utf-8"))


def load_stream(name: str) -> tuple[Event, ...]:
    """A golden event stream (a JSON array of events)."""
    target = FIXTURES_DIR / "streams" / f"{name}.json"
    return _EVENTS.validate_json(target.read_text(encoding="utf-8"))


def load_fixture_texts(subdir: str, pattern: str = "*.json") -> tuple[str, ...]:
    """The raw text of every fixture file under `fixtures/<subdir>` matching `pattern`, by name.

    The caller validates the text into its own model; this keeps all fixture file reading in
    this module.
    """
    root = FIXTURES_DIR / subdir
    return tuple(path.read_text(encoding="utf-8") for path in sorted(root.glob(pattern)))
