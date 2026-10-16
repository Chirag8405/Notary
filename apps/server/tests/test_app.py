from fastapi.testclient import TestClient
from pydantic import TypeAdapter

from notary_core.models import CHECK_ORDER, Event
from notary_server.app import create_app

client = TestClient(create_app(event_delay=0))


def test_health() -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_attacks_listed() -> None:
    assert len(client.get("/attacks").json()) == 14


def test_openapi_exposes_ws_free_rest_surface() -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert {"/health", "/scenarios", "/attacks"} <= set(paths)


def test_ws_streams_typed_events() -> None:
    adapter: TypeAdapter[Event] = TypeAdapter(Event)
    with client.websocket_connect("/ws/runs/poisoned_bill") as ws:
        events = [adapter.validate_json(ws.receive_text()) for _ in range(11)]
    assert events[0].type == "run_started"
    assert events[-1].type == "run_finished"
    decisions = [e for e in events if e.type == "decision_made"]
    assert all(tuple(r.check for r in d.decision.reasons) == CHECK_ORDER for d in decisions)
