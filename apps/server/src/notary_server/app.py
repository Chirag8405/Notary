"""FastAPI application: REST for metadata, WebSocket for the typed event stream."""

import json
import os
import secrets
from collections.abc import Callable, Mapping
from typing import Annotated, Literal

import anyio
from fastapi import FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BeforeValidator, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.websockets import WebSocketDisconnected

from notary_core.models import (
    ArenaStartCommand,
    AttackCase,
    HijackedToolCallCommand,
    NotaryModel,
    PoisonWorldCommand,
)
from notary_server.anchors import Anchor, AnchorStore
from notary_server.arena import ArenaError, ArenaResult, ArenaService, AttackerFactory
from notary_server.commands import (
    CLOSE_BAD_REQUEST,
    CLOSE_MODE_UNAVAILABLE,
    CLOSE_UNKNOWN_SCENARIO,
    CommandContext,
    CommandRejected,
    CommandRouter,
)
from notary_server.endorsement import EndorsementBroker, PendingList
from notary_server.envfile import load_env_file
from notary_server.hijacked import (
    HijackedError,
    HijackedSession,
    HijackedSessions,
    HijackedStart,
    HijackedState,
    HijackedStep,
)
from notary_server.log_redaction import attach_redaction
from notary_server.playground import (
    AttackRunResponse,
    LaneRunner,
    PlaygroundError,
    PlaygroundService,
    PoisonResponse,
)
from notary_server.read_token import TOKEN_HEADER, TOKEN_QUERY_PARAM, read_key, valid_token
from notary_server.runner import scenario_names
from notary_server.sources import (
    CheckedSource,
    RunMode,
    RunRequest,
    RunSource,
    RunUnavailableError,
    default_sources,
)
from notary_server.wiring import Settings, build_app
from notary_world.golden import EVENT_ADAPTER
from notary_world.loader import load_attacks
from notary_world.scenarios import golden_run_id

EVENT_DELAY_SECONDS = 0.4

BROKER_MODES: frozenset[RunMode] = frozenset({"cassette", "live"})
"""The run modes that escalate through the endorsement broker. `golden` never does."""


class Health(NotaryModel):
    status: Literal["ok"]


class ScenarioList(NotaryModel):
    scenarios: tuple[str, ...]


def _json_mode[M: NotaryModel](model: type[M]) -> Callable[[object], object]:
    """Validate a decoded JSON body the way the socket does (JSON mode), not as Python objects.

    The command models are strict, and strict Python-mode validation rejects a JSON array for
    a tuple field such as `lanes`. Re-encoding keeps the contract's own rules and its 422.
    """

    def validate(value: object) -> object:
        if isinstance(value, dict):
            return model.model_validate_json(json.dumps(value))
        return value

    return validate


PoisonBody = Annotated[PoisonWorldCommand, BeforeValidator(_json_mode(PoisonWorldCommand))]
ArenaBody = Annotated[ArenaStartCommand, BeforeValidator(_json_mode(ArenaStartCommand))]


class ModeList(NotaryModel):
    modes: tuple[RunMode, ...]


class _Progress:
    """What the receiver needs to know about the sender."""

    def __init__(self) -> None:
        self.run_id: str | None = None


async def _send_events(
    websocket: WebSocket,
    source: RunSource,
    request: RunRequest,
    event_delay: float,
    progress: _Progress,
) -> None:
    """Send every event of the run as one text frame.

    The source is iterated in worker threads. A worker step cannot be cancelled, so a cancelled
    stream waits for the step in flight and then closes the iterator (running its `finally`).
    """
    events = await run_in_threadpool(source.events, request)
    try:
        while (event := await run_in_threadpool(next, events, None)) is not None:
            await anyio.lowlevel.checkpoint()  # a cancel that arrived during the step lands here
            progress.run_id = event.run_id
            await websocket.send_text(EVENT_ADAPTER.dump_json(event).decode("utf-8"))
            await anyio.sleep(event_delay)
    finally:
        with anyio.CancelScope(shield=True):
            close = getattr(events, "close", None)
            if callable(close):
                await run_in_threadpool(close)


async def _receive_commands(
    websocket: WebSocket, router: CommandRouter, request: RunRequest, progress: _Progress
) -> CommandRejected | None:
    """Route client frames until one is rejected (returned) or the client disconnects (None)."""
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return None
        raw: object = message.get("text")
        try:
            if not isinstance(raw, str):
                raise CommandRejected(CLOSE_BAD_REQUEST, "invalid command")
            context = CommandContext(run_id=progress.run_id, lane=request.lane, owner=request.owner)
            router.dispatch(raw, context)
        except CommandRejected as rejected:
            return rejected


def create_app(
    event_delay: float = EVENT_DELAY_SECONDS,
    sources: Mapping[RunMode, RunSource] | None = None,
    router: CommandRouter | None = None,
    lane_runner: LaneRunner | None = None,
    hijacked: HijackedSessions | None = None,
    anchors: AnchorStore | None = None,
    attacker_llm: AttackerFactory | None = None,
    arena_max_rounds: int = 10,
    broker: EndorsementBroker | None = None,
    server_key: bytes | None = None,
) -> FastAPI:
    """`server_key` keys the read tokens (#235). Leave it out: it is made here, kept in memory only,
    and a restart drops every key together with every card. A test passes one to compute keys."""
    attach_redaction()  # the read token must never reach a log
    token_key = secrets.token_bytes(32) if server_key is None else server_key
    run_sources = default_sources() if sources is None else sources
    command_router = CommandRouter() if router is None else router
    if broker is not None:
        command_router.register("endorsement_decision", broker.handler())
    playground = PlaygroundService(lane_runner)
    hijacked_sessions = HijackedSessions() if hijacked is None else hijacked
    anchor_store = AnchorStore() if anchors is None else anchors
    arena = ArenaService(lane_runner, attacker_llm, max_rounds=arena_max_rounds)
    app = FastAPI(title="NOTARY server", version="0.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.get("/health", operation_id="getHealth")
    def health() -> Health:
        return Health(status="ok")

    @app.get("/scenarios", operation_id="listScenarios")
    def scenarios() -> ScenarioList:
        return ScenarioList(scenarios=scenario_names())

    @app.get("/attacks", operation_id="listAttacks")
    def attacks() -> list[AttackCase]:
        return list(load_attacks())

    @app.get("/runs/modes", operation_id="listRunModes")
    def run_modes() -> ModeList:
        return ModeList(modes=tuple(sorted(run_sources)))

    @app.exception_handler(PlaygroundError)
    def playground_error(_request: Request, error: PlaygroundError) -> JSONResponse:
        return JSONResponse({"detail": error.detail}, status_code=error.status)

    @app.exception_handler(HijackedError)
    def hijacked_error(_request: Request, error: HijackedError) -> JSONResponse:
        return JSONResponse({"detail": error.detail}, status_code=error.status)

    @app.post("/playground/hijacked", operation_id="startHijacked")
    def start_hijacked(request: HijackedStart) -> HijackedSession:
        return hijacked_sessions.start(request)

    @app.post("/playground/hijacked/{session_id}/calls", operation_id="submitHijackedCall")
    def submit_hijacked_call(session_id: str, command: HijackedToolCallCommand) -> HijackedStep:
        return hijacked_sessions.submit(session_id, command)

    @app.get("/playground/hijacked/{session_id}", operation_id="getHijacked")
    def get_hijacked(session_id: str) -> HijackedState:
        return hijacked_sessions.state(session_id)

    @app.exception_handler(RunUnavailableError)
    def run_unavailable(_request: Request, error: RunUnavailableError) -> JSONResponse:
        return JSONResponse({"detail": error.reason}, status_code=501)

    @app.exception_handler(ArenaError)
    def arena_error(_request: Request, error: ArenaError) -> JSONResponse:
        return JSONResponse({"detail": error.detail}, status_code=error.status)

    @app.post("/playground/arena", operation_id="startArena")
    def start_arena(command: ArenaBody) -> ArenaResult:
        return arena.run(command)

    @app.post("/playground/poison", operation_id="poisonWorld")
    def poison_world(command: PoisonBody) -> PoisonResponse:
        return playground.poison(command)

    @app.post("/playground/attacks/{attack_id}/run", operation_id="runAttack")
    def run_attack(attack_id: str) -> AttackRunResponse:
        return playground.run_attack(attack_id)

    @app.get("/runs/{run_id}/endorsements", operation_id="listEndorsements")
    def run_endorsements(
        run_id: str, token: Annotated[str | None, Header(alias=TOKEN_HEADER)] = None
    ) -> PendingList:
        """The unresolved cards of the sockets that hold this read token. A missing, malformed or
        wrong token lists nothing and is still a 200: the answer never tells a guess from a run
        that does not exist. The token reads only; answering needs the socket (#235)."""
        if broker is None or token is None or not valid_token(token):
            return PendingList(pending=())
        return PendingList(
            pending=broker.pending_for_reader(run_id, read_key(token_key, run_id, token))
        )

    @app.get("/runs/{run_id}/anchor", operation_id="getAnchor")
    def run_anchor(run_id: str) -> Anchor:
        anchor = anchor_store.get(run_id)
        if anchor is None:
            raise HTTPException(status_code=404, detail="no anchor for this run")
        return anchor

    @app.websocket("/ws/runs/{scenario}")
    async def run_stream(
        websocket: WebSocket, scenario: str, lane: str = "notary", mode: str = "golden"
    ) -> None:
        await websocket.accept()
        try:
            request = RunRequest.model_validate(
                {
                    "scenario": scenario,
                    "lane": lane,
                    "mode": mode,
                    "owner": secrets.token_urlsafe(16),
                }
            )
        except ValidationError:
            await websocket.close(code=CLOSE_BAD_REQUEST, reason="invalid run request")
            return
        source = run_sources.get(request.mode)
        if source is None:
            await websocket.close(code=CLOSE_MODE_UNAVAILABLE, reason="mode not available")
            return
        if isinstance(source, CheckedSource):
            try:
                source.check_available()
            except RunUnavailableError as unavailable:
                await websocket.close(code=unavailable.code, reason=unavailable.reason)
                return
        if request.mode in BROKER_MODES:
            # The sockets that own cards need a read token; a golden socket owns none. The
            # reason is a fixed phrase: no part of the query is ever echoed.
            tokens = websocket.query_params.getlist(TOKEN_QUERY_PARAM)
            token = tokens[0] if len(tokens) == 1 else None
            if token is None or not valid_token(token):
                await websocket.close(code=CLOSE_BAD_REQUEST, reason="invalid token")
                return
            run_id = golden_run_id(request.scenario, request.lane)
            request = request.model_copy(update={"read_key": read_key(token_key, run_id, token)})

        progress = _Progress()

        def release_run() -> None:
            """A run that is no longer watched must not wait for a human: reject its cards.

            Only the modes that escalate through the broker own cards. A golden run never
            registers one, and golden and cassette runs share the run id `run-<scenario>-<lane>`,
            so a closing golden socket must not reject the card of a cassette run (#194). The
            cancel is scoped to this socket's own run: a tab of the same scenario and lane has
            another owner and keeps its card (#201).
            """
            if request.mode in BROKER_MODES and broker is not None and progress.run_id is not None:
                broker.cancel_run(progress.run_id, owner=request.owner)

        async with anyio.create_task_group() as group:

            async def send() -> None:
                try:
                    await _send_events(websocket, source, request, event_delay, progress)
                except RunUnavailableError as unavailable:
                    await websocket.close(code=unavailable.code, reason=unavailable.reason)
                except KeyError:
                    await websocket.close(code=CLOSE_UNKNOWN_SCENARIO, reason="unknown scenario")
                except (WebSocketDisconnect, WebSocketDisconnected):
                    release_run()
                else:
                    await websocket.close()
                group.cancel_scope.cancel()

            async def receive() -> None:
                rejected = await _receive_commands(websocket, command_router, request, progress)
                release_run()
                if rejected is not None:
                    await websocket.close(code=rejected.code, reason=rejected.reason)
                group.cancel_scope.cancel()

            group.start_soon(send)
            group.start_soon(receive)

    return app


load_env_file()  # a local `.env` supplies names the shell did not set (see .env.example)
app = build_app(Settings.from_env(os.environ))
