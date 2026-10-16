"""Agent runner and world host. For now: replays hard-coded typed scenarios."""

from collections.abc import Callable, Iterator

from notary_core.models import Event
from notary_world.golden import EVENT_ADAPTER, golden_streams


def _scenarios() -> dict[str, Callable[[], tuple[Event, ...]]]:
    """Scenario name -> golden stream. `poisoned_bill` is the NOTARY lane run (the default)."""
    streams = golden_streams()
    table: dict[str, Callable[[], tuple[Event, ...]]] = {
        name: (lambda events=events: events) for name, events in streams.items()
    }
    table["poisoned_bill"] = table["poisoned_bill.notary"]
    return table


SCENARIOS = _scenarios()


class ScenarioNotFoundError(KeyError):
    """Raised for an unknown scenario name."""


def scenario_names() -> tuple[str, ...]:
    return tuple(sorted(SCENARIOS))


def scenario_events(name: str) -> Iterator[str]:
    """Yield each event of the scenario as a JSON string, validated by the Event model."""
    factory = SCENARIOS.get(name)
    if factory is None:
        raise ScenarioNotFoundError(name)
    for event in factory():
        yield EVENT_ADAPTER.dump_json(event).decode("utf-8")
