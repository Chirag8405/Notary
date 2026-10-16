from types import MappingProxyType

import pytest

from notary_core.canon import sha256_hex
from notary_core.policy.sensitive_params import (
    DEFAULT_POLICY,
    assert_covered,
    unclassified_params,
)
from notary_world.state import ToolDescription, seed_world
from notary_world.tools import (
    TOOL_SPECS,
    TOOLS_MISSING_FROM_POLICY,
    as_gateway_results,
    call,
    default_manifest_hash,
    get_tool,
    manifest_infos,
    param_unit,
    tool_manifest_hash,
    world_policy,
)

TOOL_NAMES = [
    "add_contact",
    "create_event",
    "delete_email",
    "get_balance",
    "list_files",
    "pay_bill",
    "post_slack",
    "read_calendar",
    "read_email",
    "read_file",
    "read_inbox",
    "read_slack",
    "send_email",
    "send_money",
]

VALID_ARGS: dict[str, dict[str, str]] = {
    "add_contact": {"name": "Eve"},
    "create_event": {"attendees": "a@b.example", "title": "x"},
    "delete_email": {"message_id": "m-oct"},
    "get_balance": {},
    "list_files": {"path": "secrets/"},
    "pay_bill": {"payee": "DE00ACME00000000000001", "amount": "1.50"},
    "post_slack": {"channel": "general", "text": "t"},
    "read_calendar": {},
    "read_email": {"message_id": "m-dec"},
    "read_file": {"path": "december.txt"},
    "read_inbox": {},
    "read_slack": {"channel": "finance"},
    "send_email": {"to": "a@b.example", "subject": "s", "body": "b"},
    "send_money": {"payee": "DE00ACME00000000000001", "amount": "1.50"},
}


@pytest.mark.invariant("I1")
def test_registry_has_the_fourteen_tools_sorted():
    assert [t.name for t in TOOL_SPECS] == TOOL_NAMES


@pytest.mark.invariant("I1")
def test_registry_lookup_helpers():
    spec = get_tool("send_email")
    assert spec is not None
    assert [(p.name, p.unit, p.required) for p in spec.params] == [
        ("to", "email", True),
        ("cc", "email", False),
        ("subject", None, True),
        ("body", None, True),
    ]
    assert get_tool("nope") is None
    assert param_unit("pay_bill", "payee") == "iban"
    assert param_unit("pay_bill", "reference") is None
    assert param_unit("pay_bill", "nope") is None
    assert param_unit("nope", "x") is None


@pytest.mark.attack("A1")
def test_unknown_tool_is_an_error_result_not_an_exception():
    state = seed_world()
    result = call(state, "launch_missiles", {})
    assert result.error == "unknown_tool"
    assert result.new_state is state
    assert result.records == ()
    assert result.effect is None


@pytest.mark.attack("A1")
def test_unknown_and_missing_params_are_error_results():
    state = seed_world()
    assert call(state, "read_inbox", {"x": "1"}).error == "unknown_param:x"
    assert call(state, "send_email", {"to": "a@b.example", "subject": "s"}).error == (
        "missing_param:body"
    )
    assert call(state, "send_email", {"to": "  ", "subject": "s", "body": "b"}).error == (
        "missing_param:to"
    )
    assert call(state, "read_inbox", {"z": "1", "b": "2"}).error == "unknown_param:b"
    # unknown params are reported before missing ones
    assert call(state, "send_email", {"bcc": "x"}).error == "unknown_param:bcc"


@pytest.mark.invariant("I2")
def test_registry_agrees_with_default_policy():
    for name, policy in DEFAULT_POLICY.items():
        spec = get_tool(name)
        assert spec is not None, name
        assert spec.effect == policy.effect, name
        assert {p.name for p in spec.params} == {b.name for b in policy.params}, name


@pytest.mark.invariant("I2")
def test_policy_gap_is_pinned():
    assert TOOLS_MISSING_FROM_POLICY == ("get_balance", "read_calendar", "read_inbox", "read_slack")
    assert (
        tuple(sorted(t.name for t in TOOL_SPECS if t.name not in DEFAULT_POLICY))
        == TOOLS_MISSING_FROM_POLICY
    )
    assert unclassified_params(DEFAULT_POLICY, manifest_infos()) == (("read_slack", "channel"),)


@pytest.mark.invariant("I2")
def test_world_policy_covers_every_tool():
    assert_covered(world_policy(), manifest_infos())


@pytest.mark.invariant("I2")
def test_world_policy_only_adds_read_rows():
    policy = world_policy()
    for name, row in DEFAULT_POLICY.items():
        assert policy[name] == row
    added = set(policy) - set(DEFAULT_POLICY)
    assert added == set(TOOLS_MISSING_FROM_POLICY)
    assert all(policy[name].effect == "read" for name in added)
    assert isinstance(policy, MappingProxyType)


@pytest.mark.attack("A10")
def test_manifest_hash_is_stable_and_tracks_the_description():
    state = seed_world()
    assert default_manifest_hash("pay_bill") == tool_manifest_hash(state, "pay_bill")
    rugged = state.model_copy(
        update={"tool_descriptions": (ToolDescription(tool="pay_bill", description="x"),)}
    )
    assert tool_manifest_hash(rugged, "pay_bill") != default_manifest_hash("pay_bill")
    assert tool_manifest_hash(rugged, "read_inbox") == default_manifest_hash("read_inbox")
    hashes = {default_manifest_hash(name) for name in TOOL_NAMES}
    assert len(hashes) == len(TOOL_NAMES)


@pytest.mark.attack("A10")
def test_manifest_hash_for_unknown_tool():
    expected = sha256_hex("unknown-tool:nope")
    assert default_manifest_hash("nope") == expected
    assert tool_manifest_hash(seed_world(), "nope") == expected


@pytest.mark.invariant("I3")
def test_as_gateway_results_prefixes_ids_and_keeps_readers():
    state = seed_world()
    inbox = as_gateway_results("c1", call(state, "read_inbox", {}))
    (first, first_readers) = inbox[0]
    assert first.record_id == "c1.m-oct"
    assert first.tool == "read_inbox"
    assert first_readers == ("*",)
    assert [f.name for f in first.fields] == ["sender", "subject", "body", "verified"]

    secret = as_gateway_results("c2", call(state, "read_file", {"path": "secrets/2fa.txt"}))
    assert secret[0][1] == ("user",)
    assert secret[0][0].record_id == "c2.secrets/2fa.txt"
    assert as_gateway_results("c3", call(state, "read_file", {"path": "nope"})) == ()


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("tool", TOOL_NAMES)
def test_every_tool_call_is_deterministic(tool: str):
    first = call(seed_world(), tool, VALID_ARGS[tool])
    second = call(seed_world(), tool, VALID_ARGS[tool])
    assert first.error is None
    assert first.model_dump_json() == second.model_dump_json()
