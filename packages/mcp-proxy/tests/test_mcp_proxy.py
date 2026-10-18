"""The stdio MCP proxy in front of a real MCP server (the toy bank in `examples/bank`)."""

import json
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import JsonValue
from stdio_session import StdioSession, proxy_command, request, tool_call

from notary_core.models import EffectExecuted
from notary_core.policy.sensitive_params import DEFAULT_POLICY
from notary_mcp_proxy.client import StdioClient
from notary_mcp_proxy.config import ProxyConfig, build_contract, build_policy
from notary_mcp_proxy.jsonrpc import JsonObject
from notary_mcp_proxy.main import build_server
from notary_mcp_proxy.mcp_backend import content_fields, decode_argument, encode_argument
from notary_mcp_proxy.server import ProxyServer

BANK = Path(__file__).resolve().parents[1] / "examples" / "bank"
ACME_IBAN = "DE00ACME00000000000001"
ATTACKER_IBAN = "DE00ATTACKER0000000001"


def _config(tmp_path: Path) -> Path:
    data = json.loads((BANK / "notary.json").read_text())
    data["server"]["command"] = [sys.executable, str(BANK / "server.py")]
    path = tmp_path / "notary.json"
    path.write_text(json.dumps(data))
    return path


@pytest.fixture
def config(tmp_path: Path) -> ProxyConfig:
    return ProxyConfig.model_validate_json(_config(tmp_path).read_bytes())


@pytest.fixture
def proxy(config: ProxyConfig) -> Iterator[ProxyServer]:
    client = StdioClient(config.server.command)
    try:
        yield build_server(config, client, run_id="run-test")
    finally:
        client.close()


def _call(proxy: ProxyServer, name: str, arguments: JsonObject) -> JsonObject:
    answer = proxy.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert answer is not None
    result = answer["result"]
    assert isinstance(result, dict)
    return result


def _text(result: JsonObject) -> str:
    content = result["content"]
    assert isinstance(content, list)
    return "\n".join(str(block["text"]) for block in content if isinstance(block, dict))


def _effects(proxy: ProxyServer) -> list[str]:
    return [e.event.tool for e in proxy.gateway.chain if isinstance(e.event, EffectExecuted)]


def test_lists_only_the_contract_tools(proxy: ProxyServer) -> None:
    answer = proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert answer is not None
    result = answer["result"]
    assert isinstance(result, dict)
    tools = result["tools"]
    assert isinstance(tools, list)
    assert sorted(str(t["name"]) for t in tools if isinstance(t, dict)) == [
        "pay_bill",
        "read_inbox",
    ]


@pytest.mark.attack("A3")
def test_poisoned_iban_is_blocked_and_never_reaches_the_bank(proxy: ProxyServer) -> None:
    inbox = _call(proxy, "read_inbox", {})
    assert inbox["isError"] is False
    assert ATTACKER_IBAN in _text(inbox)
    paid = _call(proxy, "pay_bill", {"payee": ATTACKER_IBAN, "amount": 120})
    assert paid["isError"] is True
    assert "LEDGER_NOT_FOUND" in _text(paid)
    assert _effects(proxy) == ["read_inbox"]


def test_ledger_payee_is_paid_with_the_schema_types(proxy: ProxyServer) -> None:
    paid = _call(proxy, "pay_bill", {"payee": ACME_IBAN, "amount": 120})
    assert paid["isError"] is False
    assert _text(paid) == f"paid 120.0 EUR to {ACME_IBAN}"
    assert _effects(proxy) == ["pay_bill"]
    assert proxy.gateway.session.spent_cents == 12000


def test_tool_outside_the_contract_is_blocked(proxy: ProxyServer) -> None:
    sent = _call(proxy, "send_email", {"to": "x@evil.example"})
    assert sent["isError"] is True
    assert "SCOPE_TOOL_NOT_IN_CONTRACT" in _text(sent)


def test_config_cannot_loosen_a_reviewed_policy_row(config: ProxyConfig) -> None:
    policy = build_policy(config)
    assert policy["pay_bill"] == DEFAULT_POLICY["pay_bill"]
    assert policy["read_inbox"].effect == "read"


def test_contract_needs_every_tool_on_the_server(config: ProxyConfig) -> None:
    with pytest.raises(ValueError, match="pay_bill"):
        build_contract(config, ())


@pytest.mark.parametrize(
    ("value", "schema_type"),
    [("text", "string"), (120, "number"), (True, "boolean"), ({"a": [1]}, "object")],
)
def test_arguments_round_trip(value: JsonValue, schema_type: str) -> None:
    assert decode_argument(encode_argument(value), schema_type) == value


def test_unparsable_number_stays_text() -> None:
    assert decode_argument("12O", "number") == "12O"


def test_non_text_blocks_are_kept_as_json() -> None:
    fields = content_fields(
        {"content": [{"type": "text", "text": "hi"}, {"type": "image", "data": "x"}]}
    )
    assert [f.name for f in fields] == ["content_000", "content_001"]
    assert fields[0].text == "hi"
    assert json.loads(fields[1].text) == {"type": "image", "data": "x"}


def test_stdio_end_to_end(tmp_path: Path) -> None:
    """The proxy as Claude Code runs it: a child process speaking MCP on stdin/stdout."""
    audit = tmp_path / "audit"
    session = StdioSession(proxy_command(_config(tmp_path), "--audit-dir", str(audit)))
    session.send(request(1, "initialize", {"protocolVersion": "x"}))
    session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    session.send(tool_call(2, "pay_bill", {"payee": ATTACKER_IBAN, "amount": 120}))
    first, second = session.result(1), session.result(2)  # read before stdin closes
    session.finish()
    assert first["protocolVersion"] == "2025-06-18"
    assert second["isError"] is True
    (chain,) = audit.glob("*.chain.jsonl")
    types = [json.loads(line)["event"]["type"] for line in chain.read_text().splitlines()]
    assert types[0] == "run_started"
    assert types[-1] == "run_finished"
    assert "effect_executed" not in types
