"""Wiring: the P3 pieces assembled into the running server (CP2).

`build_app` is the only place that decides which source answers which mode, which LLM client
backs it, and which decider answers an escalation. Environment access is limited to
`Settings.from_env` (the `NOTARY_*` variables and whether `GROQ_API_KEY` is set, never
its value). A cassette miss, a missing cassette or a missing key is an error with a
fixed reason; no mode ever falls back to another.
"""

from collections.abc import Callable, Iterator, Mapping
from typing import Annotated

from fastapi import FastAPI
from pydantic import Field

from notary_core.models import Event, Lane, NotaryModel
from notary_server.agent_runner import (
    EscalationAnnouncer,
    EscalationDecider,
    ServerAgentRunner,
    ignore_escalation,
    reject_all,
)
from notary_server.anchors import AnchorStore, anchored_append
from notary_server.arena import AttackerFactory
from notary_server.commands import CLOSE_CASSETTE_MISS, CLOSE_MODE_UNAVAILABLE
from notary_server.endorsement import EndorsementBroker, EndorsementRun
from notary_server.groq_client import GroqClient
from notary_server.lanes import lane_hooks, stream_for_lane
from notary_server.llm import DEFAULT_MODEL, CassetteClient, CassetteMissError, LlmClient
from notary_server.playground import LaneRunner
from notary_server.runner import ScenarioNotFoundError
from notary_server.sources import (
    GoldenSource,
    RunMode,
    RunRequest,
    RunSource,
    RunUnavailableError,
)
from notary_world.loader import load_cassette
from notary_world.scenarios import Scenario, get_scenario, golden_run_id

DEFAULT_ANCHOR_DB = ":memory:"
DEFAULT_ENDORSEMENT_TIMEOUT_SECONDS = 300.0
DEFAULT_ARENA_MAX_ROUNDS = 10
LIVE_RUN_NOTE = "live run: a real model answered, so this run is not reproducible"
"""Appended to the `run_finished` summary of every live run (the event contract has no field for
it). A cassette or golden run never carries it."""


class Settings(NotaryModel):
    anchor_db: Annotated[str, Field(min_length=1)] = DEFAULT_ANCHOR_DB
    """SQLite path of the audit anchors; `:memory:` loses them on restart."""
    endorsement_timeout_seconds: Annotated[float, Field(gt=0, allow_inf_nan=False)] = (
        DEFAULT_ENDORSEMENT_TIMEOUT_SECONDS
    )
    arena_max_rounds: Annotated[int, Field(ge=1, le=100)] = DEFAULT_ARENA_MAX_ROUNDS
    live_available: bool = False
    """Whether `GROQ_API_KEY` is set. Only the fact is kept, never the key."""
    live_model: Annotated[str, Field(min_length=1)] = DEFAULT_MODEL
    """The Groq chat model `live` mode asks (`NOTARY_LIVE_MODEL`). Cassettes always use
    `DEFAULT_MODEL`: the model is part of every cassette key."""

    @staticmethod
    def from_env(environ: Mapping[str, str]) -> "Settings":
        """Read `NOTARY_ANCHOR_DB`, `NOTARY_ENDORSEMENT_TIMEOUT`, `NOTARY_ARENA_MAX_ROUNDS`.

        An invalid number raises `ValueError` (at startup, not at the first request).
        """
        values: dict[str, object] = {"live_available": bool(environ.get("GROQ_API_KEY"))}
        live_model = environ.get("NOTARY_LIVE_MODEL")
        if live_model is not None:
            values["live_model"] = live_model
        anchor_db = environ.get("NOTARY_ANCHOR_DB")
        if anchor_db is not None:
            values["anchor_db"] = anchor_db
        timeout = environ.get("NOTARY_ENDORSEMENT_TIMEOUT")
        if timeout is not None:
            values["endorsement_timeout_seconds"] = _number(
                "NOTARY_ENDORSEMENT_TIMEOUT", timeout, float
            )
        rounds = environ.get("NOTARY_ARENA_MAX_ROUNDS")
        if rounds is not None:
            values["arena_max_rounds"] = _number("NOTARY_ARENA_MAX_ROUNDS", rounds, int)
        return Settings.model_validate(values)


def _number[N: (int, float)](name: str, raw: str, parse: Callable[[str], N]) -> N:
    try:
        return parse(raw)
    except ValueError:
        raise ValueError(f"{name} is not a valid number") from None


def cassette_note(model: str) -> str:
    """Appended to the `run_finished` summary of a cassette run: who produced the answers.

    The committed cassettes say `scripted-v1`: a scripted agent wrote them, no model did."""
    kind = "scripted agent" if model.startswith("scripted") else f"model {model}"
    return f"cassette replay: recorded from a {kind} ({model})"


def load_cassette_client(name: str) -> CassetteClient:
    """A replay client for `name`; a missing file is an error, never a fallback."""
    try:
        return CassetteClient(load_cassette(name))
    except FileNotFoundError:
        raise RunUnavailableError(CLOSE_CASSETTE_MISS, "cassette not found") from None


def _guard(events: Iterator[Event]) -> Iterator[Event]:
    """Turn a cassette miss into a run that cannot be served, whatever the transport."""
    try:
        yield from events
    except CassetteMissError:
        raise RunUnavailableError(CLOSE_CASSETTE_MISS, "cassette miss") from None


class RunStreamer:
    """Runs the agent runner on one lane and shapes the stream for that lane."""

    def __init__(self, *, broker: EndorsementBroker, anchors: AnchorStore) -> None:
        self._broker = broker
        self._anchors = anchors

    def stream(
        self,
        scenario: Scenario,
        lane: Lane,
        run_id: str,
        llm: LlmClient,
        decide: EscalationDecider,
        announce: EscalationAnnouncer = ignore_escalation,
        *,
        model: str = DEFAULT_MODEL,
        run_note: str = "",
    ) -> Iterator[Event]:
        runner = ServerAgentRunner(
            llm=llm,
            scenarios=lambda _name: scenario,
            decide_escalation=decide,
            announce_escalation=announce,
            audit_append=anchored_append(self._anchors),
            model=model,
            run_note=run_note,
        )
        run = runner.run(
            lane=lane, scenario=scenario.scenario_id, run_id=run_id, hooks=lane_hooks(lane)
        )
        return _guard(stream_for_lane(run, lane))

    def socket_endorsements(self, scenario: Scenario, run_id: str) -> EndorsementRun:
        """Escalations of a watched run wait for the user's command (fail closed on timeout)."""
        return self._broker.start_run(run_id, max_approvals=scenario.contract.budget.max_approvals)

    def lane_runner(self) -> LaneRunner:
        """For the REST endpoints: replays the lane's cassette and rejects every escalation."""

        def run(scenario: Scenario, lane: Lane, run_id: str) -> Iterator[Event]:
            client = load_cassette_client(f"{scenario.scenario_id}.{lane}")
            return self.stream(
                scenario, lane, run_id, client, reject_all, run_note=cassette_note(client.model)
            )

        return run


def _scenario(name: str) -> Scenario:
    try:
        return get_scenario(name)
    except ValueError:
        raise ScenarioNotFoundError(name) from None


class CassetteSource:
    """Stage run: replays the recorded LLM responses of `<scenario>.<lane>`, byte for byte."""

    def __init__(self, streamer: RunStreamer) -> None:
        self._streamer = streamer

    def events(self, request: RunRequest) -> Iterator[Event]:
        scenario = _scenario(request.scenario)
        run_id = golden_run_id(request.scenario, request.lane)
        client = load_cassette_client(f"{request.scenario}.{request.lane}")
        endorsements = self._streamer.socket_endorsements(scenario, run_id)
        return self._streamer.stream(
            scenario,
            request.lane,
            run_id,
            client,
            endorsements.decide,
            endorsements.announce,
            run_note=cassette_note(client.model),
        )


class LiveSource:
    """Live run on the Groq API. The client is built on the first request, never earlier."""

    def __init__(
        self,
        streamer: RunStreamer,
        *,
        available: bool,
        client_factory: Callable[[], LlmClient] = GroqClient,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self._streamer = streamer
        self._available = available
        self._factory = client_factory
        self._model = model
        self._client: LlmClient | None = None

    def events(self, request: RunRequest) -> Iterator[Event]:
        if not self._available:  # before the scenario lookup: no key is 4501 whatever the name
            raise RunUnavailableError(CLOSE_MODE_UNAVAILABLE, "mode not available")
        return self.run(_scenario(request.scenario), request.lane)

    def run(self, scenario: Scenario, lane: Lane) -> Iterator[Event]:
        """The live run of an already built scenario (the model probe varies the world seed)."""
        if not self._available:
            raise RunUnavailableError(CLOSE_MODE_UNAVAILABLE, "mode not available")
        if self._client is None:
            self._client = self._factory()
        run_id = golden_run_id(scenario.scenario_id, lane)
        endorsements = self._streamer.socket_endorsements(scenario, run_id)
        return self._streamer.stream(
            scenario,
            lane,
            run_id,
            self._client,
            endorsements.decide,
            endorsements.announce,
            model=self._model,
            run_note=LIVE_RUN_NOTE,
        )


def arena_attackers() -> AttackerFactory:
    def attacker(lane: Lane) -> LlmClient:
        return load_cassette_client(f"arena.{lane}")

    return attacker


def build_app(settings: Settings, *, event_delay: float = 0.4) -> FastAPI:
    from notary_server.app import create_app

    anchors = AnchorStore(settings.anchor_db)
    broker = EndorsementBroker(timeout_seconds=settings.endorsement_timeout_seconds)
    streamer = RunStreamer(broker=broker, anchors=anchors)
    sources: dict[RunMode, RunSource] = {
        "golden": GoldenSource(),
        "cassette": CassetteSource(streamer),
        "live": LiveSource(
            streamer,
            available=settings.live_available,
            model=settings.live_model,
        ),
    }
    return create_app(
        event_delay=event_delay,
        sources=sources,
        lane_runner=streamer.lane_runner(),
        anchors=anchors,
        attacker_llm=arena_attackers(),
        arena_max_rounds=settings.arena_max_rounds,
        broker=broker,
    )
