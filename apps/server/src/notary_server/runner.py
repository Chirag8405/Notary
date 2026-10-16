"""Agent runner and world host. For now: replays hard-coded typed scenarios."""

from collections.abc import Iterator

from notary_world.sample_run import EVENT_ADAPTER, poisoned_bill_events

SCENARIOS = {"poisoned_bill": poisoned_bill_events}


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
