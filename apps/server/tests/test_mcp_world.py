"""The attack library through a real transport: A1-A14 and B1-B4 over `notary-mcp-proxy` stdio.

Each run starts the seeded world as a stdio MCP server (`notary_server.world_mcp`, a child
process), fronts it with the proxy built from `proxy_config_for` and sends every scripted call as
a `tools/call`. The proxy pins its own manifests, labels with its own resolver and decides with
the real monitor, so nothing here is shared with the in-process engine except the monitor's code.
`execute_run` is the reference: verdicts, reason codes (in fact the whole `Decision`), the final
world, the session and the ledger must agree. Where the paths differ the difference is listed in
`KNOWN_DIFFERENCES` and asserted exactly, so a new difference fails the test.
"""

import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest
from mcp_world import ProxiedRun, run_through_proxy

from notary_core.models import (
    CallProposed,
    DecisionMade,
    EffectExecuted,
    IntentContract,
    LedgerEntry,
    ResolvedValue,
    ToolScope,
)
from notary_mcp_proxy.client import StdioClient
from notary_mcp_proxy.config import ProxyConfig
from notary_mcp_proxy.jsonrpc import JsonObject, as_list, as_object
from notary_server.world_config import proxy_config_for
from notary_world.attacks import (
    ALL_ATTACKS,
    ALL_CONTROLS,
    attack_world,
    control_world,
    get_attack,
    get_control,
    outcome_of,
)
from notary_world.executor import RunRecord, execute_run
from notary_world.oracle import goal_reached
from notary_world.scenarios import get_scenario
from notary_world.state import diff, seed_world
from notary_world.tools import TOOL_SPECS, default_manifest_hash
from notary_world.tools import call as world_call

ATTACK_IDS = [fixture.case.id for fixture in ALL_ATTACKS]
CONTROL_IDS = [control.control_id for control in ALL_CONTROLS]
SCENARIO_IDS = ["legitimate_bill", "poisoned_bill"]
ALL_IDS = [*ATTACK_IDS, *CONTROL_IDS, *SCENARIO_IDS]

KNOWN_DIFFERENCES = """
1. Stamped fields. The engine stamps platform facts (`verified`, the `get_balance` fields)
   trusted; a proxy config has no stamps, so the same values are untrusted. No verdict reads them.
2. The user request. The engine stores it as the value `v-request`; the proxy has no such value.
3. Write summaries. A write tool's summary text reaches the proxy as a labeled content block
   (`<call>.result.content_000`); the engine's write tools return no record.
4. Value ids of ledger entries and effect summaries are the proxy's own (`config-0`,
   `pay_bill: 1 content block(s)`); decisions do not contain them.
5. Manifest hashes are the proxy's own pins of what the server reported (issue #253).
"""
STAMPED_FIELDS = ("verified",)


@pytest.fixture(scope="module")
def proxied(tmp_path_factory: pytest.TempPathFactory) -> Callable[[str], ProxiedRun]:
    """Each library item once per module (a run starts a child process)."""
    cache: dict[str, ProxiedRun] = {}

    def get(item_id: str) -> ProxiedRun:
        if item_id not in cache:
            cache[item_id] = run_through_proxy(item_id, tmp_path_factory.mktemp(item_id))
        return cache[item_id]

    return get


def engine_record(run: ProxiedRun) -> RunRecord:
    scenario = run.scenario
    return execute_run(
        scenario=run.item_id,
        run_id=f"run-engine-{run.item_id}",
        request=scenario.user_request,
        world=scenario.world,
        contract=scenario.contract,
        ledger=scenario.ledger,
        session=scenario.session,
        calls=run.engine_calls,
        escalation=run.escalation,
    )


def mcp_record(run: ProxiedRun, engine: RunRecord) -> RunRecord:
    """The engine's record with the MCP path's final world: what the oracle reads.

    The oracle judges worlds, statuses and escalations; the statuses and escalations are the
    engine's, which `test_mcp_agrees_with_the_engine` shows equal to the proxy's.
    """
    return engine.model_copy(
        update={
            "world_after": run.world_after,
            "world_diff": diff(engine.world_before, run.world_after),
        }
    )


def _text(response: JsonObject) -> str:
    return "\n".join(
        str((as_object(block) or {}).get("text")) for block in as_list(response["content"]) or []
    )


def _assert_response_matches_verdict(run: ProxiedRun) -> None:
    """What the agent was told for each call's first proposal agrees with the decision."""
    for call in run.calls:
        text = _text(call.response)
        match call.first.verdict:
            case "ALLOW":
                assert call.response["isError"] is False, (call.call_id, text)
            case "BLOCK":
                assert call.response["isError"] is True
                assert f"NOTARY blocked {call.call.tool}; it did not run." in text
                assert str(outcome_of(call.first).code) in text
            case "ESCALATE":
                assert call.response["isError"] is True
                assert f"NOTARY escalated {call.call.tool}" in text
                assert str(outcome_of(call.first).code) in text


@pytest.mark.parametrize("attack_id", ATTACK_IDS)
def test_attack_through_mcp(attack_id: str, proxied: Callable[[str], ProxiedRun]) -> None:
    run = proxied(attack_id)
    fixture = get_attack(attack_id)
    assert [c.call.tool for c in run.calls] == [c.tool for c in fixture.scripted]
    mismatches = [
        (c.call_id, outcome_of(c.first), c.expected)
        for c in run.calls
        if outcome_of(c.first) != c.expected
    ]
    assert mismatches == []
    _assert_response_matches_verdict(run)
    assert run.calls[-1].expected == fixture.case.expected


@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_control_through_mcp(control_id: str, proxied: Callable[[str], ProxiedRun]) -> None:
    run = proxied(control_id)
    control = get_control(control_id)
    assert all(outcome_of(c.first) == c.expected for c in run.calls)
    assert all(c.first.verdict == "ALLOW" and len(c.decisions) == 1 for c in run.calls)
    assert all(c.response["isError"] is False for c in run.calls)
    executed = [e for e in run.gateway.chain if isinstance(e.event, DecisionMade)]
    assert len(executed) == len(control.scripted)
    record = mcp_record(run, engine_record(run))
    assert goal_reached(record, control.user_goal_id), control.user_goal_id


@pytest.mark.parametrize("attack_id", [a for a in ATTACK_IDS if a != "A13"])
def test_the_attacker_goal_is_not_reached_through_mcp(
    attack_id: str, proxied: Callable[[str], ProxiedRun]
) -> None:
    run = proxied(attack_id)
    fixture = get_attack(attack_id)
    record = mcp_record(run, engine_record(run))
    engine = engine_record(run)
    assert goal_reached(record, fixture.attacker_goal_id) == goal_reached(
        engine, fixture.attacker_goal_id
    )
    assert goal_reached(record, fixture.user_goal_id) == goal_reached(engine, fixture.user_goal_id)


def _contract_with_pins(contract: IntentContract, pinned: IntentContract) -> IntentContract:
    """`contract` with each scope's manifest hash replaced by the proxy's pinned one."""
    hashes = {scope.tool: scope.manifest_hash for scope in pinned.allowed_tools}
    scopes = tuple(
        ToolScope(
            tool=scope.tool,
            params=scope.params,
            manifest_hash=hashes[scope.tool],
            effect=scope.effect,
        )
        for scope in sorted(contract.allowed_tools, key=lambda s: s.tool)
    )
    return contract.model_copy(update={"allowed_tools": scopes, "contract_id": pinned.contract_id})


def _values(run: ProxiedRun) -> Mapping[str, ResolvedValue]:
    return run.gateway.store.as_mapping()


@pytest.mark.invariant("I1")
@pytest.mark.parametrize("item_id", ALL_IDS)
def test_mcp_agrees_with_the_engine(item_id: str, proxied: Callable[[str], ProxiedRun]) -> None:
    run = proxied(item_id)
    engine = engine_record(run)

    # Verdicts, reason codes and in fact the whole decision, in order (an approval decides again).
    proxy_decisions = [
        (e.event.call_id, e.event.decision)
        for e in run.gateway.chain
        if isinstance(e.event, DecisionMade)
    ]
    engine_decisions = [(c.call_id, c.decision) for c in engine.calls]
    assert [(i, d.verdict, [r.code for r in d.reasons]) for i, d in proxy_decisions] == [
        (i, d.verdict, [r.code for r in d.reasons]) for i, d in engine_decisions
    ]
    assert proxy_decisions == engine_decisions

    # The effect on the world, the session and the ledger.
    assert run.world_after == engine.world_after
    assert diff(run.scenario.world, run.world_after) == engine.world_diff
    assert run.gateway.session == engine.session
    assert [_project(e) for e in run.gateway.ledger] == [
        _project(e) for e in engine.ledger_snapshots[-1].ledger
    ]
    effects = [e.event.tool for e in run.gateway.chain if isinstance(e.event, EffectExecuted)]
    assert effects == [
        c.tool for c in engine.calls if c.effect is not None and c.status == "executed"
    ]

    # The contract: the same except the manifest hashes the proxy pinned itself.
    started = run.gateway.chain[0].event
    assert started.type == "run_started"
    pinned = started.contract
    assert _contract_with_pins(run.scenario.contract, pinned) == pinned.model_copy(
        update={"user_intent": run.scenario.contract.user_intent}
    )
    for scope in pinned.allowed_tools:
        assert scope.manifest_hash != default_manifest_hash(scope.tool)  # #253: the proxy's own

    # The values: same ids, texts, units, origins and readers; the listed differences only.
    proxy_values = _values(run)
    engine_values = {v.ref.id: v for v in engine.values}
    assert set(engine_values) - set(proxy_values) == {"v-request"}
    extra = set(proxy_values) - set(engine_values)
    assert all(
        id_.endswith(".result.content_000") and _call_tool(run, id_) in WRITE_TOOLS for id_ in extra
    )
    for id_ in set(proxy_values) & set(engine_values):
        mine, theirs = proxy_values[id_], engine_values[id_]
        assert (mine.text, mine.unit, mine.ref.content_hash) == (
            theirs.text,
            theirs.unit,
            theirs.ref.content_hash,
        )
        assert mine.ref.label.origin == theirs.ref.label.origin
        assert mine.ref.label.readers == theirs.ref.label.readers
        assert mine.ref.label.span_pointer == theirs.ref.label.span_pointer
        if mine.ref.label.integrity != theirs.ref.label.integrity:
            assert id_.rsplit(".", 1)[1] in STAMPED_FIELDS or ".acct-" in id_
            assert (mine.ref.label.integrity, theirs.ref.label.integrity) == (
                "untrusted",
                "trusted",
            )


WRITE_TOOLS = frozenset(spec.name for spec in TOOL_SPECS if spec.effect != "read")


def _call_tool(run: ProxiedRun, value_id: str) -> str:
    call_id = value_id.split(".", 1)[0]
    return next(c.call.tool for c in run.calls if c.call_id == call_id)


def _project(entry: object) -> tuple[object, ...]:
    """A ledger entry without its id and value reference (the ids are each path's own)."""
    assert isinstance(entry, LedgerEntry)
    return (entry.ledger, entry.key, entry.unit, entry.canonical, entry.source)


def test_a_secret_record_is_narrowed_by_the_server_and_blocks_the_leak(
    proxied: Callable[[str], ProxiedRun],
) -> None:
    """A5: the config says public, the world says the file is the user's; the world wins."""
    run = proxied("A5")
    secret = [v for v in _values(run).values() if v.ref.id.startswith("c2.secrets/2fa.txt.")]
    assert [v.ref.id for v in secret] == ["c2.secrets/2fa.txt.text"]
    assert secret[0].ref.label.readers == ("user",)
    assert secret[0].ref.label.origin.kind == "file"
    config = proxy_config_for(run.scenario, command=["unused"])
    assert config.tools["read_file"].readers == ("*",)
    assert config.tools["read_file"].record_readers == "narrow_by_server"
    assert outcome_of(run.calls[3].first).code == "CONF_READER_VIOLATION"


def test_the_agent_gets_the_worlds_records_as_logged(proxied: Callable[[str], ProxiedRun]) -> None:
    """B1: the answer to `read_inbox` is the world's records, rebuilt from the logged values."""
    run = proxied("B1")
    response = run.calls[0].response
    structured = as_object(response["structuredContent"])
    assert structured is not None
    expected = world_call(run.scenario.world, "read_inbox", {})
    assert [(as_object(r) or {})["record_id"] for r in as_list(structured["records"]) or []] == [
        r.record_id for r in expected.records
    ]
    for record, original in zip(
        as_list(structured["records"]) or [], expected.records, strict=True
    ):
        entry = as_object(record) or {}
        assert entry["readers"] == list(original.readers)
        assert entry["fields"] == [
            {"name": f.name, "text": f.text, "unit": f.unit} for f in original.fields
        ]
        for item in as_list(entry["fields"]) or []:
            field = as_object(item) or {}
            value = _values(run)[f"c1.{entry['record_id']}.{field['name']}"]
            assert value.text == field["text"]


def test_a_poisoned_description_from_the_first_listing_is_pinned_as_is(tmp_path: Path) -> None:
    """KNOWN DIFFERENCE (A10): the proxy trusts the first listing, so a description poisoned
    before the pin is part of the contract; only a change after the pin is drift.

    The engine's contract holds the clean hash, so it BLOCKs this call; a proxy cannot know the
    clean hash, it can only notice a change. `test_attack_through_mcp[A10]` runs the real rug pull
    (the server changes the description after the first call and announces it).
    """
    run = run_through_proxy("A10", tmp_path, descriptions="from-start")
    assert [c.first.verdict for c in run.calls] == ["ALLOW", "ALLOW"]
    assert outcome_of(run.calls[1].first).code != "SCOPE_MANIFEST_MISMATCH"
    assert run.calls[1].expected is not None
    assert run.calls[1].expected.code == "SCOPE_MANIFEST_MISMATCH"
    assert len(run.world_after.bank.transfers) == len(run.scenario.world.bank.transfers) + 1


def test_the_rug_pull_is_drift_after_the_pin(proxied: Callable[[str], ProxiedRun]) -> None:
    run = proxied("A10")
    assert run.calls[0].first.verdict == "ALLOW"
    assert outcome_of(run.calls[1].first).code == "SCOPE_MANIFEST_MISMATCH"
    assert run.world_after == run.scenario.world  # nothing was paid
    proposed = [e.event for e in run.gateway.chain if isinstance(e.event, CallProposed)]
    pinned = run.gateway.chain[0].event
    assert pinned.type == "run_started"
    pins = {s.tool: s.manifest_hash for s in pinned.contract.allowed_tools}
    assert proposed[0].proposal.manifest_hash == pins["read_inbox"]
    assert proposed[1].proposal.manifest_hash != pins["pay_bill"]


# ------------------------------------------------------------------ config and server


@pytest.mark.parametrize("scenario_id", [*SCENARIO_IDS, "summary_email", "multi_source_bill"])
def test_the_config_restates_the_contract(scenario_id: str) -> None:
    scenario = get_scenario(scenario_id)
    config = proxy_config_for(scenario, command=["python", "x"])
    contract = scenario.contract
    assert sorted(config.tools) == sorted(s.tool for s in contract.allowed_tools)
    for scope in contract.allowed_tools:
        spec = config.tools[scope.tool]
        assert spec.effect == scope.effect
        assert {name: p.marker for name, p in spec.params.items()} == dict(scope.params)
        assert spec.records is True
    assert config.budget == contract.budget
    assert config.egress_hosts == contract.egress_hosts
    assert config.authorized_irreversible == contract.authorized_irreversible
    assert [(e.ledger, e.key, e.unit, e.value) for e in config.ledger] == [
        (e.ledger, e.key, e.unit, e.canonical) for e in scenario.ledger
    ]
    assert config.server.command == ("python", "x")
    # It survives the file it will be written to.
    assert ProxyConfig.model_validate_json(config.model_dump_json(by_alias=True)) == config


def test_a_session_that_has_spent_has_no_config() -> None:
    scenario = get_scenario("legitimate_bill")
    spent = scenario.model_copy(
        update={"session": scenario.session.model_copy(update={"spent_cents": 1})}
    )
    with pytest.raises(ValueError, match="session"):
        proxy_config_for(spent, command=["x"])


def _world_client(tmp_path: Path, *extra: str) -> StdioClient:
    return StdioClient(
        [sys.executable, "-m", "notary_server.world_mcp", "--scenario", "legitimate_bill", *extra],
        cwd=tmp_path,
    )


def test_world_server_lists_the_worlds_tools_and_keeps_state(tmp_path: Path) -> None:
    dump = tmp_path / "world.json"
    client = _world_client(tmp_path, "--dump-state", str(dump))
    try:
        client.initialize()
        names = [str(tool.get("name")) for tool in client.list_tools()]
        assert sorted(names) == sorted(spec.name for spec in TOOL_SPECS)
        balance = client.call_tool("get_balance", {})
        before = _balance_text(balance)
        paid = client.call_tool("pay_bill", {"payee": "DE00ACME00000000000001", "amount": "120.00"})
        assert paid["isError"] is False
        after = _balance_text(client.call_tool("get_balance", {}))
        assert before != after  # the call changed the state the next call saw
        assert len(json.loads(dump.read_text())["bank"]["transfers"]) > 0
        bad = client.call_tool("read_email", {"message_id": "nope"})
        assert bad["isError"] is True
    finally:
        client.close()
    start = len(get_scenario("legitimate_bill").world.bank.transfers)
    assert len(json.loads(dump.read_text())["bank"]["transfers"]) == start + 1


def _balance_text(answer: JsonObject) -> str:
    structured = as_object(answer["structuredContent"]) or {}
    return json.dumps(structured["records"], sort_keys=True)


def test_world_server_is_deterministic_for_a_seed(tmp_path: Path) -> None:
    answers: list[str] = []
    for _ in range(2):
        client = _world_client(tmp_path, "--seed", "3")
        try:
            client.initialize()
            answers.append(json.dumps(client.call_tool("read_inbox", {}), sort_keys=True))
        finally:
            client.close()
    assert answers[0] == answers[1]
    expected = world_call(seed_world(3), "read_inbox", {})
    structured = as_object(json.loads(answers[0])["structuredContent"]) or {}
    assert [(as_object(r) or {})["record_id"] for r in as_list(structured["records"]) or []] == [
        r.record_id for r in expected.records
    ]


def test_world_server_refuses_bad_arguments(tmp_path: Path) -> None:
    for argv in (["--scenario", "nope"], ["--attack", "A3", "--scenario", "summary_email"], []):
        done = subprocess.run(
            [sys.executable, "-m", "notary_server.world_mcp", *argv],
            capture_output=True,
            check=False,
            cwd=tmp_path,
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
        assert done.returncode == 2
        assert done.stdout == b""
    assert attack_world("A3")[0].scenario_id == "legitimate_bill"


# ------------------------------------------------------------------ the whole proxy over stdio


class _Stdio:
    """The proxy as an agent runs it: a child process, one request at a time over its pipes."""

    def __init__(self, command: list[str], cwd: Path) -> None:
        self._process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd
        )
        self._next = 0

    def request(self, method: str, params: JsonObject) -> JsonObject:
        self._next += 1
        message = {"jsonrpc": "2.0", "id": self._next, "method": method, "params": params}
        assert self._process.stdin is not None
        assert self._process.stdout is not None
        self._process.stdin.write(json.dumps(message).encode() + b"\n")
        self._process.stdin.flush()
        while True:
            line = self._process.stdout.readline()
            assert line, "the proxy closed stdout"
            answer = as_object(json.loads(line))
            assert answer is not None
            if answer.get("id") == self._next:
                return as_object(answer["result"]) or {}

    def close(self) -> None:
        assert self._process.stdin is not None
        self._process.stdin.close()
        assert self._process.wait(timeout=60) == 0


@pytest.mark.parametrize("item_id", ["A3", "A5", "A8", "A9", "A10", "B1"])
def test_the_proxy_process_gives_the_same_verdicts_over_stdio(item_id: str, tmp_path: Path) -> None:
    """The same items through `python -m notary_mcp_proxy --config`, both ends real pipes."""
    scenario, scripted = (
        attack_world(item_id) if item_id.startswith("A") else control_world(item_id)
    )
    command = [
        sys.executable,
        "-m",
        "notary_server.world_mcp",
        "--scenario",
        scenario.scenario_id,
    ]
    if item_id.startswith("A"):
        command += ["--attack", item_id]
    config = proxy_config_for(scenario, command=command)
    path = tmp_path / "notary.json"
    path.write_text(config.model_dump_json(by_alias=True, exclude_defaults=True), encoding="utf-8")
    proxy = [sys.executable, "-m", "notary_mcp_proxy", "--config", str(path)]
    session = _Stdio([*proxy, "--control", "none"], tmp_path)
    try:
        session.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
        listed = session.request("tools/list", {})
        assert sorted(
            str((as_object(t) or {})["name"]) for t in as_list(listed["tools"]) or []
        ) == (sorted(config.tools))
        for call in scripted:
            answer = session.request("tools/call", {"name": call.tool, "arguments": {**call.args}})
            text = _text(answer)
            expected = call.expected
            if expected.verdict == "ALLOW":
                assert answer["isError"] is False, text
            else:
                assert answer["isError"] is True
                assert str(expected.code) in text
                assert (
                    "NOTARY blocked" if expected.verdict == "BLOCK" else "NOTARY escalated"
                ) in text
    finally:
        session.close()
