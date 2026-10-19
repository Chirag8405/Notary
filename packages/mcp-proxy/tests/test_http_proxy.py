"""The proxy in front of a server that speaks Streamable HTTP (the toy bank, bridged locally)."""

import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from http_fake import StdioBridge
from stdio_session import StdioSession, proxy_command, request, tool_call

from notary_core.models import DecisionMade, EffectExecuted
from notary_mcp_proxy.config import HttpServerSpec, ProxyConfig, resolve_headers
from notary_mcp_proxy.http_client import HttpClient
from notary_mcp_proxy.jsonrpc import JsonObject, as_list, as_object
from notary_mcp_proxy.main import build_server
from notary_mcp_proxy.server import ProxyServer

BANK = Path(__file__).resolve().parents[1] / "examples" / "bank"
ACME_IBAN = "DE00ACME00000000000001"
ATTACKER_IBAN = "DE00ATTACKER0000000001"
TOKEN = "s3cret-token-value"


@pytest.fixture
def bridge() -> Iterator[StdioBridge]:
    started = StdioBridge([sys.executable, str(BANK / "server.py")])
    yield started
    started.close()


def _config(url: str) -> JsonObject:
    data = json.loads((BANK / "notary.json").read_text())
    data["server"] = {
        "kind": "http",
        "url": url,
        "headers": {"Authorization": "Bearer ${BANK_TOKEN}"},
    }
    return data


def _verdicts(proxy: ProxyServer) -> list[tuple[str, str]]:
    return [
        (entry.event.call_id, entry.event.decision.verdict)
        for entry in proxy.gateway.chain
        if isinstance(entry.event, DecisionMade)
    ]


def _call(proxy: ProxyServer, call_id: int, name: str, arguments: JsonObject) -> JsonObject:
    answer = proxy.handle(tool_call(call_id, name, arguments))
    assert answer is not None
    result = as_object(answer["result"])
    assert result is not None
    return result


def _text(result: JsonObject) -> str:
    return "\n".join(str((as_object(b) or {})["text"]) for b in as_list(result["content"]) or [])


def test_the_demo_verdicts_through_an_http_server(bridge: StdioBridge) -> None:
    config = ProxyConfig.model_validate_json(json.dumps(_config(bridge.url)))
    spec = config.servers["default"]
    assert isinstance(spec, HttpServerSpec)
    headers = resolve_headers("default", spec, {"BANK_TOKEN": TOKEN})
    client = HttpClient(spec.url, headers=headers)
    try:
        proxy = build_server(config, client, run_id="run-test")
        inbox = _call(proxy, 1, "read_inbox", {})
        assert inbox["isError"] is False
        assert ATTACKER_IBAN in _text(inbox)
        blocked = _call(proxy, 2, "pay_bill", {"payee": ATTACKER_IBAN, "amount": 120})
        assert blocked["isError"] is True
        assert "LEDGER_NOT_FOUND" in _text(blocked)
        paid = _call(proxy, 3, "pay_bill", {"payee": ACME_IBAN, "amount": 120})
        assert paid["isError"] is False
        assert _text(paid) == f"paid 120.0 EUR to {ACME_IBAN}"
    finally:
        client.close()
    assert [verdict for _, verdict in _verdicts(proxy)] == ["ALLOW", "BLOCK", "ALLOW"]
    assert [e.event.tool for e in proxy.gateway.chain if isinstance(e.event, EffectExecuted)] == [
        "read_inbox",
        "pay_bill",
    ]
    # The blocked call never reached the bank; every request carried the session and the token.
    calls = [item for item in bridge.seen if item.method == "tools/call"]
    assert [(item.body or {}).get("params") for item in calls if item.body] == [
        {"name": "read_inbox", "arguments": {}},
        {"name": "pay_bill", "arguments": {"payee": ACME_IBAN, "amount": 120}},
    ]
    assert all(item.headers["authorization"] == f"Bearer {TOKEN}" for item in bridge.seen)
    sessioned = [item for item in bridge.seen if item.method != "initialize"]
    assert all(item.headers["mcp-session-id"] == "bridge-1" for item in sessioned)


def test_a_full_run_resolves_the_token_from_the_environment_and_never_prints_it(
    bridge: StdioBridge, tmp_path: Path
) -> None:
    path = tmp_path / "notary.json"
    path.write_text(json.dumps(_config(bridge.url)))
    command = proxy_command(path)
    session = StdioSession(command, env={**os.environ, "BANK_TOKEN": TOKEN})
    session.send(request(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}))
    session.send(request(2, "tools/list"))
    session.send(tool_call(3, "read_inbox", {}))
    answers = [session.answer(i) for i in (1, 2, 3)]
    assert as_object(answers[2].get("result")) is not None
    session.send(tool_call(4, "pay_bill", {"payee": ATTACKER_IBAN, "amount": 120}))
    blocked = as_object(session.answer(4).get("result")) or {}
    assert blocked["isError"] is True
    stderr = session.finish()
    assert TOKEN not in json.dumps(answers)
    assert TOKEN not in stderr
    assert bridge.url in stderr  # what is fronted is logged; the headers are not
    assert all(item.headers["authorization"] == f"Bearer {TOKEN}" for item in bridge.seen)
    assert bridge.seen[-1].verb == "POST"
