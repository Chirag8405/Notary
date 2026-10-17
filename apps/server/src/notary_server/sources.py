"""Run sources: where the events of a run come from (golden replay now; cassette and live later)."""

from collections.abc import Iterator, Mapping
from typing import Literal, Protocol, runtime_checkable

from notary_core.models import Event, Lane, NotaryModel
from notary_server.runner import ScenarioNotFoundError
from notary_world.golden import golden_streams

RunMode = Literal["golden", "cassette", "live"]


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
    owner: str = ""
    """The server-side identity of the socket (see `CommandContext.owner`). The socket sets it;
    it is never read from the query. Empty outside a socket."""
    read_key: bytes | None = None
    """`HMAC(server_key, run_id, token)` of the socket's read token (#235), or None. Only the
    digest is kept; the raw token never reaches a source."""


class RunSource(Protocol):
    def events(self, request: RunRequest) -> Iterator[Event]:
        """Return the events of the run. Raise `KeyError` (or `ScenarioNotFoundError`) for an
        unknown scenario. The iterator may block: the server drives it from a worker thread."""
        ...


@runtime_checkable
class CheckedSource(Protocol):
    """A source that can say at once that it cannot serve any run (no key). The socket asks
    before it reads the token, so "mode not available" (4501) wins over "invalid token" (4400)."""

    def check_available(self) -> None:
        """Raise `RunUnavailableError` when the source cannot serve."""
        ...


class GoldenSource:
    """The hand-built P0b streams, named `<scenario>.<lane>`.

    A scenario name is served under the requested lane. A full stream name
    (`poisoned_bill.undefended`) is still served as that stream, but only when no stream exists
    for `<name>.<lane>`.
    """

    def events(self, request: RunRequest) -> Iterator[Event]:
        streams = golden_streams()
        events = streams.get(f"{request.scenario}.{request.lane}") or streams.get(request.scenario)
        if events is None:
            raise ScenarioNotFoundError(request.scenario)
        return iter(events)


def default_sources() -> Mapping[RunMode, RunSource]:
    return {"golden": GoldenSource()}
