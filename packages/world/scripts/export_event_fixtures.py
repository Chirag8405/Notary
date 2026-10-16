"""Serialise the golden event streams to JSON fixtures that the TS side parses with Zod."""

import sys
from pathlib import Path

from pydantic import TypeAdapter

from notary_core.models import Event
from notary_world.golden import COMMAND_ADAPTER, golden_streams, sample_commands

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
OUT = FIXTURES / "streams"
COMMANDS = FIXTURES / "commands"
_STREAM: TypeAdapter[tuple[Event, ...]] = TypeAdapter(tuple[Event, ...])


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in OUT.glob("*.json"):
        stale.unlink()
    for name, events in golden_streams().items():
        payload = _STREAM.dump_json(events, indent=2).decode("utf-8")
        (OUT / f"{name}.json").write_text(payload + "\n", encoding="utf-8")
    COMMANDS.mkdir(parents=True, exist_ok=True)
    for stale in COMMANDS.glob("*.json"):
        stale.unlink()
    for name, command in sample_commands().items():
        payload = COMMAND_ADAPTER.dump_json(command, indent=2).decode("utf-8")
        (COMMANDS / f"{name}.json").write_text(payload + "\n", encoding="utf-8")
    sys.stdout.write(f"wrote {len(golden_streams())} golden streams and commands\n")


if __name__ == "__main__":
    main()
