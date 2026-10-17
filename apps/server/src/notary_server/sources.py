"""Run sources: where the events of a run come from (golden replay now; cassette and live later)."""

from collections.abc import Iterator, Mapping
from typing import Literal, Protocol

from notary_core.models import Event, Lane, NotaryModel
from notary_server.runner import ScenarioNotFoundError
from notary_world.golden import golden_streams

RunMode = Literal["golden", "cassette", "live"]

SCENARIO_ALIASES = {"poisoned_bill": "poisoned_bill.notary"}
"""Short scenario names served by the golden source (`poisoned_bill` is the NOTARY lane run)."""


class RunUnavailableError(Exception):
    """A source cannot serve this run (no key, no cassette, a cassette miss).

    The socket closes with `code` and the fixed `reason`; it never falls back to another mode.
    """

    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


class RunRequest(NotaryModel):
    scenario: str
    lane: Lane
    mode: RunMode


class RunSource(Protocol):
    def events(self, request: RunRequest) -> Iterator[Event]:
        """Return the events of the run. Raise `KeyError` (or `ScenarioNotFoundError`) for an
        unknown scenario. The iterator may block: the server drives it from a worker thread."""
        ...


class GoldenSource:
    """The hand-built P0b streams. The lane is ignored: the stream name already carries it."""

    def events(self, request: RunRequest) -> Iterator[Event]:
        streams = golden_streams()
        events = streams.get(SCENARIO_ALIASES.get(request.scenario, request.scenario))
        if events is None:
            raise ScenarioNotFoundError(request.scenario)
        return iter(events)


def default_sources() -> Mapping[RunMode, RunSource]:
    return {"golden": GoldenSource()}
