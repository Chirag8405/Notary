"""G28: every tool on the scanned MCP surfaces declares all four annotation hints as booleans."""

import importlib.util
from pathlib import Path

import pytest

from notary_mcp_proxy.jsonrpc import JsonObject, as_list, as_object
from notary_server.world_mcp import tool_definitions
from notary_world.scenarios import get_scenario
from notary_world.tools import TOOL_SPECS, ToolSpec, tool_annotations

HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
BANK = Path(__file__).resolve().parents[3] / "packages/mcp-proxy/examples/bank/server.py"


def _world_tools() -> list[JsonObject]:
    state = get_scenario("legitimate_bill").world
    return [d for raw in tool_definitions(state) if (d := as_object(raw)) is not None]


def _bank_tools() -> list[JsonObject]:
    spec = importlib.util.spec_from_file_location("bank_server", BANK)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    listed = as_list(module.TOOLS) or []
    return [t for raw in listed if (t := as_object(raw)) is not None]


def _assert_four_booleans(tool: JsonObject) -> None:
    annotations = as_object(tool.get("annotations"))
    assert annotations is not None, f"{tool['name']} has no annotations"
    assert set(annotations) == set(HINTS), tool["name"]
    for hint in HINTS:
        assert isinstance(annotations[hint], bool), f"{tool['name']}.{hint} is not a boolean"


def test_world_server_lists_every_registry_tool_with_four_boolean_hints() -> None:
    tools = _world_tools()
    assert {str(t["name"]) for t in tools} == {s.name for s in TOOL_SPECS}
    assert len(tools) == 14
    for tool in tools:
        _assert_four_booleans(tool)


def test_bank_server_lists_every_tool_with_four_boolean_hints() -> None:
    tools = _bank_tools()
    assert {str(t["name"]) for t in tools} == {"read_inbox", "pay_bill", "add_contact"}
    for tool in tools:
        _assert_four_booleans(tool)


@pytest.mark.parametrize("spec", TOOL_SPECS, ids=lambda s: s.name)
def test_hints_agree_with_the_effect_class(spec: ToolSpec) -> None:
    hints = tool_annotations(spec)
    assert hints["readOnlyHint"] is (spec.effect == "read")
    assert hints["destructiveHint"] is (spec.effect == "irreversible")
    if spec.effect == "read":
        assert hints["idempotentHint"] is True
        assert hints["openWorldHint"] is False


def test_served_hints_are_the_derived_hints() -> None:
    by_name = {s.name: tool_annotations(s) for s in TOOL_SPECS}
    for tool in _world_tools():
        assert tool["annotations"] == by_name[str(tool["name"])]


def test_bank_hints_agree_with_the_world_for_the_shared_tools() -> None:
    by_name = {s.name: tool_annotations(s) for s in TOOL_SPECS}
    for tool in _bank_tools():
        name = str(tool["name"])
        expected = by_name[name]
        if name == "add_contact":
            # the toy bank keeps a name list on the server: nothing leaves it
            expected = {**expected, "openWorldHint": False}
        assert tool["annotations"] == expected, name


def test_outbound_tools_are_open_world_and_local_writes_are_not() -> None:
    by_name = {s.name: tool_annotations(s) for s in TOOL_SPECS}
    for name in ("pay_bill", "send_money", "send_email", "post_slack", "create_event"):
        assert by_name[name]["openWorldHint"] is True
    for name in ("add_contact", "delete_email"):
        assert by_name[name]["openWorldHint"] is False


def test_a_write_tool_added_without_hint_row_fails() -> None:
    spec = ToolSpec(name="new_tool", description="x", effect="write", params=())
    with pytest.raises(KeyError):
        tool_annotations(spec)
