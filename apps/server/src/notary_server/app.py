"""FastAPI application: REST for metadata, WebSocket for the typed event stream."""

import ipaddress
import json
import os
import secrets
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Annotated, Literal

import anyio
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
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
from notary_server.endorsement import EndorsementBroker
from notary_server.envfile import load_env_file
from notary_server.hijacked import (
    HijackedError,
    HijackedSession,
    HijackedSessions,
    HijackedStart,
    HijackedState,
    HijackedStep,
)
from notary_server.limits import PlaygroundLimits, RateLimitedError, RateLimiter
from notary_server.log_redaction import attach_redaction
from notary_server.mcp_runs import McpApprovals, McpRunList, list_mcp_runs
from notary_server.playground import (
    AttackRunResponse,
    LaneRunner,
    PlaygroundError,
    PlaygroundService,
    PoisonResponse,
)
from notary_server.runner import scenario_names
from notary_server.sources import (
    RunMode,
    RunRequest,
    RunSource,
    RunUnavailableError,
    default_sources,
)
from notary_server.wiring import Settings, build_app
from notary_world.golden import EVENT_ADAPTER
from notary_world.loader import load_attacks

EVENT_DELAY_SECONDS = 0.4
WEB_ORIGINS = ["http://localhost:3000"]
"""The pages allowed to call the server from a browser (CORS), and the only ones whose socket may
approve an MCP escalation."""
FORWARDING_HEADERS = ("forwarded", "x-forwarded-for", "x-forwarded-host", "x-real-ip")
"""Set by a reverse proxy. A socket that carries one is not a local client, whatever address the
proxy connects from."""

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


class _End:
    """What `next` returns when a source has no more events (a source may also yield `None`)."""


_END = _End()


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
    A `None` from the source means "nothing new yet" and sends nothing.
    """
    events = await run_in_threadpool(source.events, request)
    try:
        while not isinstance(event := await run_in_threadpool(next, events, _END), _End):
            await anyio.lowlevel.checkpoint()  # a cancel that arrived during the step lands here
            if event is None:
                continue
            progress.run_id = event.run_id
            await websocket.send_text(EVENT_ADAPTER.dump_json(event).decode("utf-8"))
            await anyio.sleep(event_delay)
    finally:
        with anyio.CancelScope(shield=True):
            close = getattr(events, "close", None)
            if callable(close):
                await run_in_threadpool(close)


def is_loopback_host(host: str | None) -> bool:
    """Whether a peer address is this machine (127.0.0.0/8, ::1, or either as an IPv4-mapped v6)."""
    if host is None:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def is_local_client(websocket: WebSocket) -> bool:
    """Whether this socket may act on an MCP escalation: a loopback peer, no reverse proxy in
    between, and (for a browser, which always sends one) an `Origin` that is the X-ray page.

    The origin test matters because a loopback peer is also any web page the user has open: a
    browser lets that page connect to `ws://localhost:8000`.
    """
    client = websocket.client
    if client is None or not is_loopback_host(client.host):
        return False
    if any(name in websocket.headers for name in FORWARDING_HEADERS):
        return False
    origin = websocket.headers.get("origin")
    return origin is None or origin in WEB_ORIGINS


async def _receive_commands(
    websocket: WebSocket,
    router: CommandRouter,
    request: RunRequest,
    progress: _Progress,
    *,
    blocking: bool = False,
) -> CommandRejected | None:
    """Route client frames until one is rejected (returned) or the client disconnects (None).

    `blocking`: the handlers do I/O (an MCP control socket), so a command is dispatched in a worker
    thread, one at a time, and the event loop is not held."""
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return None
        raw: object = message.get("text")
        try:
            if not isinstance(raw, str):
                raise CommandRejected(CLOSE_BAD_REQUEST, "invalid command")
            context = CommandContext(run_id=progress.run_id, lane=request.lane, owner=request.owner)
            if blocking:
                await run_in_threadpool(router.dispatch, raw, context)
            else:
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
    limits: PlaygroundLimits | None = None,
    mcp_runs_dir: Path | None = None,
    mcp_approvals: McpApprovals | None = None,
) -> FastAPI:
    """`limits` are the per-client rate limits of the playground POSTs (#242). `build_app` always
    passes them; without them (the default here) nothing is limited, which is what most tests
    want. `mcp_runs_dir` is the directory of the MCP proxy's audit chains
    (`NOTARY_MCP_RUNS_DIR`); without it `GET /mcp/runs` answers 404. `mcp_approvals`
    (`NOTARY_MCP_APPROVALS=1`) lets the endorsement card approve or reject an MCP proxy
    escalation; without it, or for a client that is not local, a command on an `mcp` socket
    closes it `4422`."""
    attach_redaction()  # a session id in a request path must never reach a log
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
        allow_origins=WEB_ORIGINS,
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

    @app.get("/mcp/runs", operation_id="listMcpRuns")
    def mcp_runs() -> McpRunList:
        # Registered either way, so the OpenAPI document (and the generated client) does not
        # depend on the environment of the process that exports it.
        if mcp_runs_dir is None:
            raise HTTPException(status_code=404, detail="mcp runs are not enabled")
        return McpRunList(runs=list_mcp_runs(mcp_runs_dir))

    @app.exception_handler(PlaygroundError)
    def playground_error(_request: Request, error: PlaygroundError) -> JSONResponse:
        return JSONResponse({"detail": error.detail}, status_code=error.status)

    @app.exception_handler(HijackedError)
    def hijacked_error(_request: Request, error: HijackedError) -> JSONResponse:
        return JSONResponse({"detail": error.detail}, status_code=error.status)

    @app.exception_handler(RateLimitedError)
    def rate_limited(_request: Request, error: RateLimitedError) -> JSONResponse:
        return JSONResponse(
            {"detail": "too many requests"},
            status_code=429,
            headers={"Retry-After": str(error.retry_after)},
        )

    def client_key(http: Request) -> str:
        """The socket peer. Behind a reverse proxy this is the proxy unless uvicorn is told to
        trust its forwarding header (deploy notes in `docs/demo.md`)."""
        return "unknown" if http.client is None else http.client.host

    def within_budget(limiter: RateLimiter | None, http: Request) -> str:
        """The client key, after charging one request to `limiter` (429 when it is over)."""
        key = client_key(http)
        if limiter is not None and not limiter.allow(key):
            raise RateLimitedError(limiter.retry_after(key))
        return key

    @app.post("/playground/hijacked", operation_id="startHijacked")
    def start_hijacked(request: HijackedStart, http: Request) -> HijackedSession:
        key = within_budget(None if limits is None else limits.starts, http)
        return hijacked_sessions.start(request, client=key)

    @app.post("/playground/hijacked/{session_id}/calls", operation_id="submitHijackedCall")
    def submit_hijacked_call(
        session_id: str, command: HijackedToolCallCommand, http: Request
    ) -> HijackedStep:
        within_budget(None if limits is None else limits.calls, http)
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
    def start_arena(command: ArenaBody, http: Request) -> ArenaResult:
        within_budget(None if limits is None else limits.runs, http)
        return arena.run(command)

    @app.post("/playground/poison", operation_id="poisonWorld")
    def poison_world(command: PoisonBody, http: Request) -> PoisonResponse:
        within_budget(None if limits is None else limits.runs, http)
        return playground.poison(command)

    @app.post("/playground/attacks/{attack_id}/run", operation_id="runAttack")
    def run_attack(attack_id: str, http: Request) -> AttackRunResponse:
        within_budget(None if limits is None else limits.runs, http)
        return playground.run_attack(attack_id)

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

        # Nothing is paced for a chain that is read from disk. An `mcp` socket has its own router:
        # without a handler every command is refused (4422). The handler that forwards an approval
        # to the proxy is registered only when approvals are enabled AND this client is local.
        reading_chain = request.mode == "mcp"
        delay = 0.0 if reading_chain else event_delay
        socket_router = CommandRouter() if reading_chain else command_router
        if reading_chain and mcp_approvals is not None and is_local_client(websocket):
            socket_router.register("endorsement_decision", mcp_approvals.handler())

        async with anyio.create_task_group() as group:

            async def send() -> None:
                try:
                    await _send_events(websocket, source, request, delay, progress)
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
                rejected = await _receive_commands(
                    websocket, socket_router, request, progress, blocking=reading_chain
                )
                release_run()
                if rejected is not None:
                    await websocket.close(code=rejected.code, reason=rejected.reason)
                group.cancel_scope.cancel()

            group.start_soon(send)
            group.start_soon(receive)

    return app


load_env_file()  # a local `.env` supplies names the shell did not set (see .env.example)
app = build_app(Settings.from_env(os.environ))
