"""`notary` CLI: fuzz | replay | bench | attack."""

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import TypeAdapter

from notary_core.models import Event
from notary_world.loader import load_attacks

app = typer.Typer(no_args_is_help=True, add_completion=False, help="NOTARY command line.")
_EVENT: TypeAdapter[Event] = TypeAdapter(Event)
_EVENTS: TypeAdapter[list[Event]] = TypeAdapter(list[Event])


def read_events(path: Path) -> list[Event]:
    """Parse a JSON file holding one event, a JSON array of events, or JSON lines."""
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("["):
        return _EVENTS.validate_json(text)
    try:
        return [_EVENT.validate_json(text)]
    except ValueError:
        return [_EVENT.validate_json(line) for line in text.splitlines() if line.strip()]


@app.command()
def replay(file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)]) -> None:
    """Print the typed events in FILE."""
    for event in read_events(file):
        typer.echo(f"[{event.seq:03d}] {event.type:<22} run={event.run_id}")


@app.command()
def bench() -> None:
    """Benchmark the monitor (stub)."""
    typer.echo("bench: not implemented yet")
    raise typer.Exit(code=2)


@app.command()
def fuzz() -> None:
    """Fuzz the monitor (stub)."""
    typer.echo("fuzz: not implemented yet")
    raise typer.Exit(code=2)


@app.command()
def attack(
    list_only: Annotated[bool, typer.Option("--list", help="List the attack library.")] = False,
) -> None:
    """Run an attack from the library (stub; --list prints A1-A14)."""
    if list_only:
        for case in load_attacks():
            typer.echo(json.dumps({"id": case.id, "category": case.category, "title": case.title}))
        return
    typer.echo("attack: not implemented yet")
    raise typer.Exit(code=2)
