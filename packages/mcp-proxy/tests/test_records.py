"""The `records` result shape: the server's record ids, readers that only narrow (#260)."""

import json
import sys
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

import pytest
from pydantic import JsonValue, ValidationError

from notary_mcp_proxy.client import StdioClient
from notary_mcp_proxy.config import ProxyConfig
from notary_mcp_proxy.jsonrpc import JsonObject, as_list, as_object
from notary_mcp_proxy.main import build_server
from notary_mcp_proxy.mcp_backend import ERR_PROTOCOL
from notary_mcp_proxy.server import ProxyServer

FAKE = Path(__file__).resolve().parent / "fake_server.py"
LOOKUP: JsonObject = {
    "name": "lookup",
    "description": "Look records up.",
    "inputSchema": {"type": "object", "properties": {}},
}
BUDGET: JsonObject = {
    "max_effects": 5,
    "max_spend_cents": 0,
    "max_egress_bytes": 0,
    "max_call_amount_cents": 0,
    "max_approvals": 0,
}

Start = Callable[..., ProxyServer]


def _config_data(
    readers: list[str], record_readers: str | None, *, records: bool = True
) -> JsonObject:
    lookup: JsonObject = {"effect": "read", "readers": list(readers), "records": records}
    if record_readers is not None:
        lookup["record_readers"] = record_readers
    return {
        "server": {"command": ["unused"]},
        "user_intent": "Look records up.",
        "tools": {"lookup": lookup},
        "budget": BUDGET,
    }


def _record(record_id: str, readers: Sequence[JsonValue] | None, *fields: JsonObject) -> JsonObject:
    record: JsonObject = {"record_id": record_id, "fields": list(fields)}
    if readers is not None:
        record["readers"] = list(readers)
    return record


def _field(name: str, text: str, unit: str | None = None) -> JsonObject:
    return {"name": name, "text": text, "unit": unit}


def _answer(*records: JsonObject, blocks: tuple[str, ...] | None = None) -> JsonObject:
    structured: JsonObject = {"records": list(records)}
    texts = (json.dumps(structured),) if blocks is None else blocks
    content: list[JsonValue] = [{"type": "text", "text": text} for text in texts]
    return {"content": content, "structuredContent": structured, "isError": False}


@pytest.fixture
def start(tmp_path: Path) -> Iterator[Start]:
    clients: list[StdioClient] = []

    def run(
        result: JsonObject, *, readers: list[str] | None = None, record_readers: str | None = None
    ) -> ProxyServer:
        script = tmp_path / "script.json"
        script.write_text(json.dumps({"tools": [LOOKUP], "results": {"lookup": result}}))
        command = [sys.executable, str(FAKE), str(script)]
        data = {**_config_data(readers or ["*"], record_readers), "server": {"command": command}}
        config = ProxyConfig.model_validate_json(json.dumps(data))
        client = StdioClient(command)
        clients.append(client)
        return build_server(config, client, run_id="run-test")

    yield run
    for client in clients:
        client.close()


def _call(proxy: ProxyServer) -> JsonObject:
    answer = proxy.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "lookup", "arguments": {}},
        }
    )
    assert answer is not None
    out = as_object(answer["result"])
    assert out is not None
    return out


def _readers(proxy: ProxyServer, value_id: str) -> tuple[str, ...]:
    value = proxy.gateway.store.get(value_id)
    assert value is not None, value_id
    return value.ref.label.readers


@pytest.mark.parametrize(
    ("config_readers", "server_readers", "expected"),
    [
        (["user"], ["*"], ("user",)),  # a server cannot make a record public
        (["*"], ["user"], ("user",)),  # a server can make a record secret
        (["*"], ["*"], ("*",)),
        (["user", "bob"], ["user", "carol"], ("user",)),
        (["user"], ["bob"], ()),  # nobody
        (["*"], [], ()),
    ],
)
def test_server_readers_only_narrow(
    start: Start, config_readers: list[str], server_readers: list[str], expected: tuple[str, ...]
) -> None:
    proxy = start(
        _answer(_record("r1", server_readers, _field("text", "hello"))),
        readers=config_readers,
        record_readers="narrow_by_server",
    )
    assert _call(proxy)["isError"] is False
    assert _readers(proxy, "c1.r1.text") == expected


@pytest.mark.parametrize(
    ("config_readers", "server_readers", "expected"),
    [(["user"], ["*"], ("user",)), (["*"], ["user"], ("*",)), (["*"], None, ("*",))],
)
def test_config_mode_ignores_the_servers_readers(
    start: Start,
    config_readers: list[str],
    server_readers: list[str] | None,
    expected: tuple[str, ...],
) -> None:
    proxy = start(
        _answer(_record("r1", server_readers, _field("text", "hello"))), readers=config_readers
    )
    assert _call(proxy)["isError"] is False
    assert _readers(proxy, "c1.r1.text") == expected


def test_records_keep_their_ids_and_the_agent_gets_the_logged_texts(start: Start) -> None:
    proxy = start(
        _answer(
            _record("m1", ["*"], _field("sender", "a@x.example"), _field("body", "Pay 5")),
            _record("notes/todo.txt", ["user"], _field("text", "secret", "identifier")),
        ),
        record_readers="narrow_by_server",
    )
    answer = _call(proxy)
    assert answer["isError"] is False
    assert sorted(proxy.gateway.store.as_mapping()) == [
        "c1.m1.body",
        "c1.m1.sender",
        "c1.notes/todo.txt.text",
    ]
    assert _readers(proxy, "c1.m1.body") == ("*",)
    assert _readers(proxy, "c1.notes/todo.txt.text") == ("user",)
    stored = proxy.gateway.store.get("c1.notes/todo.txt.text")
    assert stored is not None
    assert stored.unit == "identifier"
    assert stored.ref.label.integrity == "untrusted"
    # The agent's answer is rebuilt from the logged values, not from what the server sent.
    assert answer["structuredContent"] == {
        "records": [
            {
                "record_id": "m1",
                "readers": ["*"],
                "fields": [
                    {"name": "sender", "text": "a@x.example", "unit": None},
                    {"name": "body", "text": "Pay 5", "unit": None},
                ],
            },
            {
                "record_id": "notes/todo.txt",
                "readers": ["user"],
                "fields": [{"name": "text", "text": "secret", "unit": "identifier"}],
            },
        ]
    }
    content = as_list(answer["content"]) or []
    compact = json.dumps(answer["structuredContent"], separators=(",", ":"))
    assert as_object(content[0]) == {"type": "text", "text": compact}
    structured = as_object(answer["structuredContent"]) or {}
    for record in as_list(structured.get("records")) or []:
        entry = as_object(record) or {}
        for item in as_list(entry["fields"]) or []:
            field = as_object(item) or {}
            value = proxy.gateway.store.get(f"c1.{entry['record_id']}.{field['name']}")
            assert value is not None
            assert value.text == field["text"]


def test_a_text_block_that_is_not_a_copy_is_labeled_with_the_tools_readers(start: Start) -> None:
    proxy = start(
        _answer(_record("r1", ["user"], _field("text", "a")), blocks=("hello from the server",)),
        readers=["*"],
        record_readers="narrow_by_server",
    )
    assert _call(proxy)["isError"] is False
    assert sorted(proxy.gateway.store.as_mapping()) == ["c1.r1.text", "c1.result.content_000"]
    assert _readers(proxy, "c1.result.content_000") == ("*",)


@pytest.mark.parametrize(
    "result",
    [
        # missing readers while narrowing
        _answer(_record("r1", None, _field("text", "a"))),
        # a duplicate record id
        _answer(_record("r1", ["*"], _field("a", "x")), _record("r1", ["*"], _field("b", "y"))),
        # the record id of argument values
        _answer(_record("arg", ["*"], _field("payee", "x"))),
        # two values with one id
        _answer(_record("a.b", ["*"], _field("c", "x")), _record("a", ["*"], _field("b.c", "y"))),
        # a duplicate field
        _answer(_record("r1", ["*"], _field("a", "x"), _field("a", "y"))),
        # an unknown unit, a stray key, a non-string readers entry
        _answer(_record("r1", ["*"], _field("a", "x", "furlongs"))),
        _answer(_record("r1", ["*"], {"name": "a", "text": "x", "unit": None, "extra": 1})),
        _answer(_record("r1", [1], _field("a", "x"))),
        {"content": [], "structuredContent": {"records": [], "other": 1}, "isError": False},
        {"content": [], "structuredContent": {"nope": []}, "isError": False},
        {"content": [], "structuredContent": [], "isError": False},
    ],
)
def test_a_result_that_is_not_the_records_shape_is_refused(
    start: Start, result: JsonObject
) -> None:
    proxy = start(result, record_readers="narrow_by_server")
    answer = _call(proxy)
    assert answer["isError"] is True
    assert ERR_PROTOCOL in json.dumps(answer)
    assert not any(
        k.startswith("c1.") and ".arg." not in k for k in proxy.gateway.store.as_mapping()
    )


def test_a_result_without_structured_content_is_labeled_as_text(start: Start) -> None:
    result: JsonObject = {"content": [{"type": "text", "text": "plain"}], "isError": False}
    proxy = start(result, record_readers="narrow_by_server")
    answer = _call(proxy)
    assert answer["isError"] is False
    assert sorted(proxy.gateway.store.as_mapping()) == ["c1.result.content_000"]


@pytest.mark.parametrize(
    "tool",
    [
        {"effect": "read", "record_readers": "narrow_by_server"},  # needs `records`
        {"effect": "read", "records": True, "fields": {"a": {"readers": ["user"]}}},
        {"effect": "read", "records": True, "record_readers": "widen"},
    ],
)
def test_bad_record_config_fails_at_load(tool: JsonObject) -> None:
    data = _config_data(["*"], None)
    data["tools"] = {"lookup": tool}
    with pytest.raises(ValidationError):
        ProxyConfig.model_validate_json(json.dumps(data))
