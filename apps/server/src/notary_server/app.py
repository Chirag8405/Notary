"""FastAPI application: REST for metadata, WebSocket for the typed event stream."""

import json
from collections.abc import Mapping
from typing import Annotated, Literal

import anyio
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BeforeValidator, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.websockets import WebSocketDisconnected

from notary_core.models import AttackCase, NotaryModel, PoisonWorldCommand
from notary_server.commands import (
    CLOSE_BAD_REQUEST,
    CLOSE_MODE_UNAVAILABLE,
    CLOSE_UNKNOWN_SCENARIO,
    CommandContext,
    CommandRejected,
    CommandRouter,
)
from notary_server.playground import (
    AttackRunResponse,
    LaneRunner,
    PlaygroundError,
    PlaygroundService,
    PoisonResponse,
)
from notary_server.runner import scenario_names
from notary_server.sources import RunMode, RunRequest, RunSource, default_sources
from notary_world.golden import EVENT_ADAPTER
from notary_world.loader import load_attacks

EVENT_DELAY_SECONDS = 0.4


class Health(NotaryModel):
    status: Literal["ok"]


class ScenarioList(NotaryModel):
    scenarios: tuple[str, ...]


def _command_from_json(value: object) -> object:
    """Validate a decoded JSON body the way the socket does (JSON mode), not as Python objects.

    The command models are strict, and strict Python-mode validation rejects a JSON array for
    a tuple field such as `lanes`. Re-encoding keeps the contract's own rules and its 422.
    """
    if isinstance(value, dict):
        return PoisonWorldCommand.model_validate_json(json.dumps(value))
    return value


PoisonBody = Annotated[PoisonWorldCommand, BeforeValidator(_command_from_json)]


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
            router.dispatch(raw, CommandContext(run_id=progress.run_id, lane=request.lane))
        except CommandRejected as rejected:
            return rejected


def create_app(
    event_delay: float = EVENT_DELAY_SECONDS,
    sources: Mapping[RunMode, RunSource] | None = None,
    router: CommandRouter | None = None,
    lane_runner: LaneRunner | None = None,
) -> FastAPI:
    run_sources = default_sources() if sources is None else sources
    command_router = CommandRouter() if router is None else router
    playground = PlaygroundService(lane_runner)
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

    @app.post("/playground/poison", operation_id="poisonWorld")
    def poison_world(command: PoisonBody) -> PoisonResponse:
        return playground.poison(command)

    @app.post("/playground/attacks/{attack_id}/run", operation_id="runAttack")
    def run_attack(attack_id: str) -> AttackRunResponse:
        return playground.run_attack(attack_id)

    @app.websocket("/ws/runs/{scenario}")
    async def run_stream(
        websocket: WebSocket, scenario: str, lane: str = "notary", mode: str = "golden"
    ) -> None:
        await websocket.accept()
        try:
            request = RunRequest.model_validate({"scenario": scenario, "lane": lane, "mode": mode})
        except ValidationError:
            await websocket.close(code=CLOSE_BAD_REQUEST, reason="invalid run request")
            return
        source = run_sources.get(request.mode)
        if source is None:
            await websocket.close(code=CLOSE_MODE_UNAVAILABLE, reason="mode not available")
            return

        progress = _Progress()
        async with anyio.create_task_group() as group:

            async def send() -> None:
                try:
                    await _send_events(websocket, source, request, event_delay, progress)
                except KeyError:
                    await websocket.close(code=CLOSE_UNKNOWN_SCENARIO, reason="unknown scenario")
                except (WebSocketDisconnect, WebSocketDisconnected):
                    pass
                else:
                    await websocket.close()
                group.cancel_scope.cancel()

            async def receive() -> None:
                rejected = await _receive_commands(websocket, command_router, request, progress)
                if rejected is not None:
                    await websocket.close(code=rejected.code, reason=rejected.reason)
                group.cancel_scope.cancel()

            group.start_soon(send)
            group.start_soon(receive)

    return app


app = create_app()
