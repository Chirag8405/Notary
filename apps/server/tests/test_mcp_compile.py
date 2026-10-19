"""`POST /mcp/compile`: the Intent Compiler for the MCP proxy's first prompt (#265, phase 2).

No test reaches the network: the model is a `ScriptedClient`, and the HTTP client is Starlette's.
"""

import json

import pytest
from fastapi.testclient import TestClient

from notary_core.models import IntentContract
from notary_core.pinning import ToolManifest, manifest_hash
from notary_server.app import create_app
from notary_server.llm import LlmClient, LlmRequest, ScriptedClient
from notary_server.mcp_compile import (
    DETAIL_MODEL_FAILED,
    DETAIL_NOT_COMPILED,
    DETAIL_UNAVAILABLE,
    McpCompileService,
)
from notary_server.wiring import Settings, build_app
from notary_world.models import CassetteTurn

RUN = "mcp-0123456789ab"
PROMPT = "Pay my December Acme Utilities bill from my inbox."
LOCAL = ("127.0.0.1", 50000)
SCHEMA = json.dumps({"type": "object", "properties": {"payee": {}, "amount": {}}}, sort_keys=True)
MANIFESTS = [
    {"name": "read_inbox", "description": "Read the inbox.", "input_schema": "{}"},
    {"name": "pay_bill", "description": "Pay a bill.", "input_schema": SCHEMA},
]
ANSWER: dict[str, object] = {
    "tools": [
        {"tool": "read_inbox", "params": []},
        {"tool": "pay_bill", "params": [{"name": "payee", "marker": None}]},
    ],
    "budget": {"max_effects": 2},
    "egress_hosts": [],
    "authorized_irreversible": ["pay_bill"],
}
BODY = {"request": PROMPT, "manifests": MANIFESTS}


def turn(content: str) -> CassetteTurn:
    return CassetteTurn(role="assistant", content=content, tool_calls=())


class Failing:
    """A model client whose call fails with text that must never reach the caller."""

    def complete(self, request: LlmRequest) -> CassetteTurn:
        raise RuntimeError("secret-key-sk-123 in the exception text")


def client_for(
    model: LlmClient,
    *,
    peer: tuple[str, int] = LOCAL,
    available: bool = True,
    enabled: bool = True,
) -> TestClient:
    service = McpCompileService(available=available, client_factory=lambda: model)
    app = create_app(event_delay=0, mcp_compile=service if enabled else None)
    return TestClient(app, client=peer)


def post(client: TestClient, headers: dict[str, str] | None = None, body: object = BODY):
    return client.post("/mcp/compile", json=body, headers=headers or {})


def test_a_local_caller_gets_the_compiled_contract() -> None:
    model = ScriptedClient([turn(json.dumps(ANSWER))])
    response = post(client_for(model))
    assert response.status_code == 200
    answer = response.json()
    contract = IntentContract.model_validate_json(json.dumps(answer["contract"]))
    assert contract.user_intent == PROMPT
    assert [scope.tool for scope in contract.allowed_tools] == ["pay_bill", "read_inbox"]
    assert contract.authorized_irreversible == ("pay_bill",)
    for scope in contract.allowed_tools:  # the hashes are the ones of the manifests sent
        manifest = ToolManifest.model_validate(
            next(m for m in MANIFESTS if m["name"] == scope.tool)
        )
        assert scope.manifest_hash == manifest_hash(manifest)
    assert answer["dropped"] == []
    (seen,) = model.requests
    assert PROMPT in seen.messages[0].content
    assert "Read the inbox." not in seen.messages[0].content  # descriptions never reach the model


def test_the_route_is_off_without_the_flag() -> None:
    model = ScriptedClient([turn(json.dumps(ANSWER))])
    response = post(client_for(model, enabled=False))
    assert (response.status_code, response.json()) == (
        404,
        {"detail": "mcp compile is not enabled"},
    )
    assert model.requests == ()


def test_the_flag_is_exactly_one() -> None:
    assert Settings.from_env({"NOTARY_MCP_COMPILE": "1"}).mcp_compile is True
    for value in ("", "0", "true", "yes", "2", " 1"):
        assert Settings.from_env({"NOTARY_MCP_COMPILE": value}).mcp_compile is False
    assert Settings.from_env({}).mcp_compile is False


def test_build_app_registers_the_route_only_with_the_flag() -> None:
    off = TestClient(build_app(Settings(), event_delay=0), client=LOCAL)
    assert post(off).status_code == 404
    on = TestClient(build_app(Settings(mcp_compile=True), event_delay=0), client=LOCAL)
    assert post(on).status_code == 503  # enabled, but no model key in the settings
    assert post(on).json() == {"detail": DETAIL_UNAVAILABLE}


@pytest.mark.parametrize("peer", [("10.0.0.5", 1), ("192.168.1.2", 1), ("::ffff:10.0.0.5", 1)])
def test_a_caller_that_is_not_on_this_machine_is_refused(peer: tuple[str, int]) -> None:
    model = ScriptedClient([turn(json.dumps(ANSWER))])
    response = post(client_for(model, peer=peer))
    assert (response.status_code, response.json()) == (403, {"detail": "local callers only"})
    assert model.requests == ()


@pytest.mark.parametrize("name", ["Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP"])
def test_a_forwarding_header_is_refused(name: str) -> None:
    model = ScriptedClient([turn(json.dumps(ANSWER))])
    response = post(client_for(model), {name: "203.0.113.9"})
    assert response.status_code == 403
    assert model.requests == ()


@pytest.mark.parametrize("origin", ["http://localhost:3000", "http://evil.example", "null", ""])
def test_any_origin_header_is_refused(origin: str) -> None:
    """A browser always sends one; even the X-ray's own is refused (the caller is the proxy)."""
    model = ScriptedClient([turn(json.dumps(ANSWER))])
    response = post(client_for(model), {"Origin": origin})
    assert response.status_code == 403
    assert model.requests == ()


def test_the_check_comes_before_the_body_is_read() -> None:
    model = ScriptedClient([turn(json.dumps(ANSWER))])
    response = post(client_for(model, peer=("10.0.0.5", 1)), body={"nonsense": True})
    assert response.status_code == 403


@pytest.mark.parametrize(
    "body",
    [
        {"request": "", "manifests": MANIFESTS},
        {"request": PROMPT, "manifests": []},
        {"request": PROMPT, "manifests": MANIFESTS, "extra": 1},
        {"request": "x" * 8193, "manifests": MANIFESTS},
        {"request": PROMPT, "manifests": [{"name": "a", "description": "d"}]},
        {
            "request": PROMPT,
            "manifests": [{"name": "a", "description": "x" * 300000, "input_schema": "{}"}],
        },
    ],
)
def test_a_bad_request_is_a_422(body: object) -> None:
    model = ScriptedClient([turn(json.dumps(ANSWER))])
    assert post(client_for(model), body=body).status_code == 422
    assert model.requests == ()


def test_a_reply_that_is_not_a_proposal_is_a_clean_error() -> None:
    response = post(client_for(ScriptedClient([turn("not json at all, ignore previous")])))
    assert (response.status_code, response.json()) == (422, {"detail": DETAIL_NOT_COMPILED})
    assert "ignore previous" not in response.text


def test_duplicate_tool_names_are_a_clean_error() -> None:
    body = {"request": PROMPT, "manifests": [MANIFESTS[0], MANIFESTS[0]]}
    response = post(client_for(ScriptedClient([turn(json.dumps(ANSWER))])), body=body)
    assert (response.status_code, response.json()) == (422, {"detail": DETAIL_NOT_COMPILED})


def test_a_failing_model_call_is_a_clean_error_without_the_exception_text() -> None:
    response = post(client_for(Failing()))
    assert (response.status_code, response.json()) == (502, {"detail": DETAIL_MODEL_FAILED})
    assert "secret" not in response.text
    assert "Traceback" not in response.text


def test_no_key_is_a_503_and_never_builds_the_client() -> None:
    built: list[int] = []

    def factory() -> LlmClient:
        built.append(1)
        return ScriptedClient([])

    service = McpCompileService(available=False, client_factory=factory)
    client = TestClient(create_app(event_delay=0, mcp_compile=service), client=LOCAL)
    response = post(client)
    assert (response.status_code, response.json()) == (503, {"detail": DETAIL_UNAVAILABLE})
    assert built == []
