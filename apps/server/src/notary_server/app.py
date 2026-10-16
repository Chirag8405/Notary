"""FastAPI application: REST for metadata, WebSocket for the typed event stream."""

import asyncio
from typing import Literal

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from notary_core.models import AttackCase, NotaryModel
from notary_server.runner import ScenarioNotFoundError, scenario_events, scenario_names
from notary_world.loader import load_attacks

EVENT_DELAY_SECONDS = 0.4


class Health(NotaryModel):
    status: Literal["ok"]


class ScenarioList(NotaryModel):
    scenarios: tuple[str, ...]


def create_app(event_delay: float = EVENT_DELAY_SECONDS) -> FastAPI:
    app = FastAPI(title="NOTARY server", version="0.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_methods=["GET"],
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

    @app.websocket("/ws/runs/{scenario}")
    async def run_stream(websocket: WebSocket, scenario: str) -> None:
        await websocket.accept()
        try:
            for payload in scenario_events(scenario):
                await websocket.send_text(payload)
                await asyncio.sleep(event_delay)
        except ScenarioNotFoundError:
            await websocket.close(code=4404, reason="unknown scenario")
            return
        except WebSocketDisconnect:
            return
        await websocket.close()

    return app


app = create_app()
