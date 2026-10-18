"""Structured tool results: one labeled value per field, per-field readers and units (#256)."""

import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import JsonValue, ValidationError

from notary_core.resolver import ArgumentResolver
from notary_mcp_proxy.client import StdioClient
from notary_mcp_proxy.config import ProxyConfig
from notary_mcp_proxy.jsonrpc import JsonObject, as_list, as_object
from notary_mcp_proxy.main import build_server
from notary_mcp_proxy.server import ProxyServer
from notary_mcp_proxy.structured import (
    MAX_LEAVES,
    Leaf,
    StructureError,
    declared,
    flatten,
    matches,
    schema_paths,
    unflatten,
)

FAKE = Path(__file__).resolve().parent / "fake_server.py"
ACME = "DE00ACME00000000000001"
SPACED = "de00 acme 0000 0000 0000 01"

OUTPUT_SCHEMA: JsonObject = {
    "type": "object",
    "properties": {
        "iban": {"type": "string"},
        "memo": {"type": "string"},
        "amount": {"type": "number"},
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"iban": {"type": "string"}, "memo": {"type": "string"}},
            },
        },
    },
}
SCHEMA: JsonObject = {"type": "object", "properties": {}}
LOOKUP: JsonObject = {
    "name": "lookup",
    "description": "Look a payee up.",
    "inputSchema": SCHEMA,
    "outputSchema": OUTPUT_SCHEMA,
}
SEND: JsonObject = {
    "name": "send_email",
    "description": "Send an email.",
    "inputSchema": {
        "type": "object",
        "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
    },
}
BUDGET: JsonObject = {
    "max_effects": 5,
    "max_spend_cents": 0,
    "max_egress_bytes": 10000,
    "max_call_amount_cents": 0,
    "max_approvals": 0,
}
FREE: JsonObject = {"marker": {"kind": "free"}}


# ---------------------------------------------------------------- flatten / unflatten

_KEYS = st.text(alphabet=st.sampled_from(list("ab.*\\#019 é")), max_size=4)
_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=8),
)
_JSON = st.recursive(
    _SCALARS,
    lambda inner: st.one_of(st.lists(inner, max_size=4), st.dictionaries(_KEYS, inner, max_size=4)),
    max_leaves=25,
)


def _same(a: JsonValue, b: JsonValue) -> bool:
    """Equal including types (1 is not 1.0, 1 is not true)."""
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


@given(_JSON)
def test_round_trip(value: JsonValue) -> None:
    leaves = flatten(value)
    assert _same(unflatten(leaves), value)
    assert len({path for path, _, _ in leaves}) == len(leaves)


@given(st.dictionaries(_KEYS, _SCALARS, max_size=6))
def test_round_trip_objects_with_awkward_keys(value: dict[str, JsonValue]) -> None:
    assert _same(unflatten(flatten(value)), value)


def test_paths_and_texts() -> None:
    value: JsonValue = {
        "iban": "DE00",
        "items": [{"amount": 1.5}, {"amount": 2}],
        "a.b": True,
        "0": None,
        "": [],
        "e": {},
    }
    assert flatten(value) == (
        ("structured.iban", "DE00", "string"),
        ("structured.items.0.amount", "1.5", "number"),
        ("structured.items.1.amount", "2", "integer"),
        ("structured.a\\.b", "true", "boolean"),
        ("structured.\\#0", "null", "null"),
        ("structured.\\#", "[]", "array"),
        ("structured.e", "{}", "object"),
    )


def test_a_dotted_key_and_a_nested_key_are_different_paths() -> None:
    nested = flatten({"a": {"b": "x"}})
    dotted = flatten({"a.b": "x"})
    assert nested[0][0] != dotted[0][0]
    assert unflatten(dotted) == {"a.b": "x"}


def test_empty_and_scalar_roots() -> None:
    assert unflatten(flatten({})) == {}
    assert unflatten(flatten("x")) == "x"


@pytest.mark.parametrize(
    "leaves",
    [
        [("structured.a", "1", "integer"), ("structured.a.b", "2", "integer")],
        [("structured.a", "1", "integer"), ("structured.a", "2", "integer")],
        [("structured.01", "1", "integer")],
        [("structured.1", "1", "integer")],
        [("structured.0", "1", "integer"), ("structured.a", "1", "integer")],
        [("structured.a", "01", "integer")],
        [("structured.a", "1.0", "integer")],
        [("structured.a", "1.50", "number")],
        [("structured.a", "yes", "boolean")],
        [("structured.a", "{ }", "object")],
        [("structured.\\#a", "x", "string")],
        [("structured.a..b", "x", "string")],
        [("structured.a\\", "x", "string")],
        [("other.a", "x", "string")],
        [("structured.a", "x", "bytes")],
        [],
    ],
)
def test_unflatten_rejects_what_flatten_never_writes(leaves: list[Leaf]) -> None:
    with pytest.raises(StructureError):
        unflatten(leaves)


def test_limits_fail_closed() -> None:
    deep: JsonValue = "x"
    for _ in range(40):
        deep = {"k": deep}
    with pytest.raises(StructureError):
        flatten(deep)
    with pytest.raises(StructureError):
        flatten(list(range(MAX_LEAVES + 1)))
    with pytest.raises(StructureError):
        flatten(float("nan"))


# ---------------------------------------------------------------- schema paths / matching


def test_schema_paths() -> None:
    assert schema_paths(OUTPUT_SCHEMA) == frozenset(
        {"iban", "memo", "amount", "items", "items.*", "items.*.iban", "items.*.memo"}
    )


def test_schema_paths_follow_refs_and_stop_on_recursion() -> None:
    schema: JsonObject = {
        "$defs": {
            "node": {
                "type": "object",
                "properties": {"name": {"type": "string"}, "next": {"$ref": "#/$defs/node"}},
            }
        },
        "allOf": [{"$ref": "#/$defs/node"}],
        "properties": {"0": {"type": "string"}, "a.b": {"type": "string"}},
    }
    assert schema_paths(schema) == frozenset({"name", "next", "\\#0", "a\\.b"})


def test_matching() -> None:
    assert matches("items.*.iban", "items.0.iban")
    assert matches("items.*.iban", "items.12.iban")
    assert not matches("items.*.iban", "items.x.iban")
    assert not matches("items.*.iban", "items.iban")
    assert not matches("iban", "iban2")
    assert not matches("*", "\\*")  # a key named "*" is not an index
    assert matches("items.0.iban", "items.0.iban")
    assert not matches("items.0.iban", "items.1.iban")


def test_declared() -> None:
    schema = schema_paths(OUTPUT_SCHEMA)
    assert declared("items.3.iban", schema)
    assert declared("iban", schema)
    assert not declared("iban2", schema)
    assert not declared("items.iban", schema)
    assert not declared("items.\\*.iban", schema)


# ---------------------------------------------------------------- config


def _config_data(fields: JsonObject | None = None, readers: list[str] | None = None) -> JsonObject:
    lookup: JsonObject = {"effect": "read", "origin": {"kind": "email"}}
    if fields is not None:
        lookup["fields"] = fields
    if readers is not None:
        lookup["readers"] = list(readers)
    return {
        "server": {"command": ["unused"]},
        "user_intent": "Look payees up and mail them.",
        "tools": {
            "lookup": lookup,
            "send_email": {
                "effect": "write",
                "params": {"to": FREE, "body": FREE},
            },
        },
        "budget": BUDGET,
        "ledger": [{"ledger": "contacts", "key": "x", "unit": "email", "value": "x@example.com"}],
    }


@pytest.mark.parametrize(
    "fields",
    [
        {"iban*": {"readers": ["user"]}},
        {"a..b": {"readers": ["user"]}},
        {"": {"readers": ["user"]}},
        {"a\\": {"readers": ["user"]}},
        {"iban": {}},
        {"iban": {"unit": "not-a-unit"}},
        {"iban": {"readers": ["user"], "extra": 1}},
    ],
)
def test_bad_field_config_fails_at_load(fields: JsonObject) -> None:
    with pytest.raises(ValidationError):
        ProxyConfig.model_validate_json(json.dumps(_config_data(fields)))


# ---------------------------------------------------------------- through the proxy

Start = Callable[..., ProxyServer]


@pytest.fixture
def start(tmp_path: Path) -> Iterator[Start]:
    clients: list[StdioClient] = []

    def run(
        result: JsonObject,
        *,
        fields: JsonObject | None = None,
        readers: list[str] | None = None,
        tools: list[JsonObject] | None = None,
    ) -> ProxyServer:
        script = tmp_path / "script.json"
        listed = [LOOKUP, SEND] if tools is None else tools
        script.write_text(json.dumps({"tools": listed, "results": {"lookup": result}}))
        command = [sys.executable, str(FAKE), str(script)]
        data = {**_config_data(fields, readers), "server": {"command": command}}
        config = ProxyConfig.model_validate_json(json.dumps(data))
        client = StdioClient(command)
        clients.append(client)
        return build_server(config, client, run_id="run-test", audit=None)

    yield run
    for client in clients:
        client.close()


def _request(proxy: ProxyServer, method: str, params: JsonObject | None = None) -> JsonObject:
    message: JsonObject = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        message["params"] = params
    answer = proxy.handle(message)
    assert answer is not None
    out = as_object(answer["result"])
    assert out is not None
    return out


def _call(proxy: ProxyServer, name: str, arguments: JsonObject | None = None) -> JsonObject:
    return _request(proxy, "tools/call", {"name": name, "arguments": arguments or {}})


def _texts(result: JsonObject) -> list[str]:
    return [str((as_object(b) or {})["text"]) for b in as_list(result["content"]) or []]


def _ok(structured: JsonObject, *texts: str, error: bool = False) -> JsonObject:
    content: list[JsonValue] = [{"type": "text", "text": text} for text in texts]
    return {"content": content, "structuredContent": structured, "isError": error}


def _readers(proxy: ProxyServer, value_id: str) -> tuple[str, ...]:
    value = proxy.gateway.store.get(value_id)
    assert value is not None, value_id
    return value.ref.label.readers


def _ids(proxy: ProxyServer) -> list[str]:
    return sorted(proxy.gateway.store.as_mapping())


def test_one_labeled_value_per_field_with_per_field_readers(start: Start) -> None:
    proxy = start(_ok({"iban": ACME, "memo": "December"}), fields={"iban": {"readers": ["user"]}})
    answer = _call(proxy, "lookup")
    assert answer["isError"] is False
    assert _ids(proxy) == ["c1.result-1.structured.iban", "c1.result.structured.memo"]
    assert _readers(proxy, "c1.result-1.structured.iban") == ("user",)
    assert _readers(proxy, "c1.result.structured.memo") == ("*",)
    iban = proxy.gateway.store.get("c1.result-1.structured.iban")
    assert iban is not None
    assert iban.text == ACME
    assert iban.ref.label.integrity == "untrusted"


def test_the_tool_readers_are_the_default_and_a_field_may_widen(start: Start) -> None:
    proxy = start(
        _ok({"iban": ACME, "memo": "December"}),
        fields={"memo": {"readers": ["*"]}},
        readers=["user"],
    )
    _call(proxy, "lookup")
    assert _readers(proxy, "c1.result.structured.iban") == ("user",)
    assert _readers(proxy, "c1.result-1.structured.memo") == ("*",)


def test_records_are_numbered_by_their_first_path(start: Start) -> None:
    proxy = start(
        _ok({"memo": "m", "iban": ACME, "amount": 3}),
        fields={
            "memo": {"readers": ["a"]},
            "iban": {"readers": ["b"]},
            "amount": {"readers": ["a"]},
        },
    )
    _call(proxy, "lookup")
    # Group "b" (first path structured.iban) comes before group "a" (structured.amount ... memo)
    assert _readers(proxy, "c1.result-1.structured.amount") == ("a",)
    assert _readers(proxy, "c1.result-1.structured.memo") == ("a",)
    assert _readers(proxy, "c1.result-2.structured.iban") == ("b",)
    assert [i for i in _ids(proxy) if "structured_types" in i] == ["c1.result.structured_types"]


def test_a_key_the_schema_does_not_declare_gets_no_field_config(start: Start) -> None:
    proxy = start(
        _ok({"iban": ACME, "iban2": ACME, "ghost": "boo"}),
        fields={"iban": {"readers": ["user"], "unit": "iban"}, "ghost": {"readers": ["user"]}},
    )
    _call(proxy, "lookup")
    assert _readers(proxy, "c1.result-1.structured.iban") == ("user",)
    assert _readers(proxy, "c1.result.structured.iban2") == ("*",)
    assert _readers(proxy, "c1.result.structured.ghost") == ("*",)  # not in the output schema
    iban2 = proxy.gateway.store.get("c1.result.structured.iban2")
    assert iban2 is not None
    assert iban2.unit is None


def test_a_tool_without_output_schema_gets_no_field_config(start: Start) -> None:
    plain: JsonObject = {k: v for k, v in LOOKUP.items() if k != "outputSchema"}
    proxy = start(_ok({"iban": ACME}), fields={"iban": {"readers": ["user"]}}, tools=[plain, SEND])
    _call(proxy, "lookup")
    assert _readers(proxy, "c1.result.structured.iban") == ("*",)


def test_array_patterns(start: Start) -> None:
    proxy = start(
        _ok({"items": [{"iban": ACME, "memo": "a"}, {"iban": "DE00OTHER", "memo": "b"}]}),
        fields={"items.*.iban": {"readers": ["user"]}},
    )
    _call(proxy, "lookup")
    assert _readers(proxy, "c1.result-1.structured.items.0.iban") == ("user",)
    assert _readers(proxy, "c1.result-1.structured.items.1.iban") == ("user",)
    assert _readers(proxy, "c1.result.structured.items.0.memo") == ("*",)
    # Items the schema does not declare as an array of objects are ignored, whatever the keys.
    other = start(_ok({"items": {"iban": ACME}}), fields={"items.*.iban": {"readers": ["user"]}})
    _call(other, "lookup")
    assert _readers(other, "c1.result.structured.items.iban") == ("*",)


def test_a_container_pattern_covers_its_leaves_and_the_most_specific_wins(start: Start) -> None:
    proxy = start(
        _ok({"items": [{"iban": ACME, "memo": "a"}]}),
        fields={
            "items": {"readers": ["user"], "unit": "identifier"},
            "items.*.memo": {"readers": ["*"]},
        },
    )
    _call(proxy, "lookup")
    assert _readers(proxy, "c1.result-1.structured.items.0.iban") == ("user",)
    assert _readers(proxy, "c1.result.structured.items.0.memo") == ("*",)
    memo = proxy.gateway.store.get("c1.result.structured.items.0.memo")
    assert memo is not None
    assert memo.unit == "identifier"  # the unit still comes from `items`


def test_a_field_unit_makes_the_resolver_reuse_the_labeled_value(start: Start) -> None:
    proxy = start(_ok({"iban": SPACED}), fields={"iban": {"readers": ["user"], "unit": "iban"}})
    _call(proxy, "lookup")
    values = proxy.gateway.store.as_mapping()
    reused = ArgumentResolver()(
        call_id="c9", tool="pay_bill", param="payee", raw=ACME, unit="iban", store=values
    )
    assert reused.ref.id == "c1.result-1.structured.iban"
    assert reused.ref.label.readers == ("user",)
    value = proxy.gateway.store.get("c1.result-1.structured.iban")
    assert value is not None
    assert value.unit == "iban"
    assert value.text == SPACED


def _mail(proxy: ProxyServer, body: str) -> str:
    answer = _call(proxy, "send_email", {"to": "x@example.com", "body": body})
    return "\n".join(_texts(answer))


def test_a_user_only_field_cannot_be_quoted_in_an_egress_payload(start: Start) -> None:
    proxy = start(
        _ok({"iban": ACME, "memo": "December invoice"}), fields={"iban": {"readers": ["user"]}}
    )
    _call(proxy, "lookup")
    assert "CONF_READER_VIOLATION" in _mail(proxy, ACME)
    assert "CONF_READER_VIOLATION" not in _mail(proxy, "December invoice")


def test_without_field_readers_the_tool_readers_let_it_through(start: Start) -> None:
    proxy = start(_ok({"iban": ACME, "memo": "December invoice"}))
    _call(proxy, "lookup")
    assert "CONF_READER_VIOLATION" not in _mail(proxy, ACME)


def test_the_agent_gets_the_server_structure_rebuilt_from_labeled_values(start: Start) -> None:
    structured: JsonObject = {
        "iban": ACME,
        "amount": 12.5,
        "memo": "7",
        "items": [{"iban": "x", "memo": "y"}, {"iban": "z", "memo": "w"}],
        "count": 2,
        "ok": True,
        "none": None,
        "empty": {},
        "list": [],
        "a.b": {"0": 1},
    }
    proxy = start(_ok(structured), fields={"iban": {"readers": ["user"]}})
    answer = _call(proxy, "lookup")
    assert _same(answer["structuredContent"], structured)
    # The string "7" stays a string, the number 2 stays a number.
    rebuilt = as_object(answer["structuredContent"]) or {}
    assert rebuilt["memo"] == "7"
    assert rebuilt["count"] == 2
    assert rebuilt["amount"] == 12.5
    # Older clients get one text block, serialized from the labeled values.
    assert [json.loads(t) for t in _texts(answer)] == [structured]


def test_tools_list_exposes_the_pinned_output_schema(start: Start) -> None:
    proxy = start(_ok({"iban": ACME}))
    listed = as_list(_request(proxy, "tools/list")["tools"]) or []
    by_name = {str((as_object(t) or {})["name"]): as_object(t) or {} for t in listed}
    assert by_name["lookup"]["outputSchema"] == OUTPUT_SCHEMA
    assert "outputSchema" not in by_name["send_email"]


def test_the_agent_sees_only_what_was_logged(start: Start) -> None:
    proxy = start(_ok({"iban": ACME, "memo": "December"}))
    answer = _call(proxy, "lookup")
    logged = {
        v.text
        for i, v in proxy.gateway.store.as_mapping().items()
        if i.startswith("c1.result.structured.")
    }
    assert logged == {ACME, "December"}
    assert answer["structuredContent"] == {"iban": ACME, "memo": "December"}


def test_a_text_block_that_copies_the_structured_content_is_not_labeled(start: Start) -> None:
    structured: JsonObject = {"iban": ACME, "memo": "December"}
    copy = json.dumps({"memo": "December", "iban": ACME}, indent=2)  # same data, other layout
    proxy = start(_ok(structured, copy, f"Found {ACME}."), fields={"iban": {"readers": ["user"]}})
    answer = _call(proxy, "lookup")
    # content_000 (the copy) is not a value: it would have let the secret out with public readers.
    assert not any(i.endswith(".content_000") for i in _ids(proxy))
    assert _readers(proxy, "c1.result.content_001") == ("*",)  # prose keeps the tool's readers
    assert _texts(answer) == [json.dumps(structured, separators=(",", ":")), f"Found {ACME}."]
    assert answer["structuredContent"] == structured
    # The copy cannot be used to quote the secret as public.
    assert "CONF_READER_VIOLATION" in _mail(proxy, ACME)


@pytest.mark.parametrize("bad", [[1, 2], "text", 5, None, True])
def test_non_object_structured_content_fails_closed(start: Start, bad: JsonValue) -> None:
    result: JsonObject = {
        "content": [{"type": "text", "text": ACME}],
        "structuredContent": bad,
        "isError": False,
    }
    proxy = start(result)
    answer = _call(proxy, "lookup")
    assert answer["isError"] is True
    assert "structuredContent" not in answer
    assert ACME not in "\n".join(_texts(answer))
    assert "broke the protocol" in "\n".join(_texts(answer))
    assert not any(i.startswith("c1.result") for i in _ids(proxy))


def test_too_many_fields_fail_closed(start: Start) -> None:
    proxy = start(_ok({"items": list(range(MAX_LEAVES + 1))}))
    answer = _call(proxy, "lookup")
    assert answer["isError"] is True
    assert not any(i.startswith("c1.result") for i in _ids(proxy))


def test_structured_content_of_a_failed_call_is_labeled_too(start: Start) -> None:
    proxy = start(_ok({"iban": ACME}, "boom", error=True), fields={"iban": {"readers": ["user"]}})
    answer = _call(proxy, "lookup")
    assert answer["isError"] is True
    assert answer["structuredContent"] == {"iban": ACME}
    assert "lookup failed: the tool reported an error" in _texts(answer)[0]
    assert _readers(proxy, "c1.result-1.structured.iban") == ("user",)


def test_text_only_results_keep_their_names(start: Start) -> None:
    result: JsonObject = {"content": [{"type": "text", "text": "plain"}], "isError": False}
    proxy = start(result)
    answer = _call(proxy, "lookup")
    assert _ids(proxy) == ["c1.result.content_000"]
    assert _texts(answer) == ["plain"]
    assert "structuredContent" not in answer
