"""Typed loaders for the JSON fixtures shipped in packages/world/fixtures."""

from pathlib import Path

from pydantic import TypeAdapter

from notary_core.models import AttackCase
from notary_world.models import Cassette, World

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"

_ATTACKS = TypeAdapter(tuple[AttackCase, ...])


def load_world(path: Path | None = None) -> World:
    target = path or FIXTURES_DIR / "world.json"
    return World.model_validate_json(target.read_text(encoding="utf-8"))


def load_attacks(path: Path | None = None) -> tuple[AttackCase, ...]:
    target = path or FIXTURES_DIR / "attacks.json"
    return _ATTACKS.validate_json(target.read_text(encoding="utf-8"))


def load_cassette(name: str) -> Cassette:
    target = FIXTURES_DIR / "cassettes" / f"{name}.json"
    return Cassette.model_validate_json(target.read_text(encoding="utf-8"))
