"""CP2: the poisoned bill replayed through the real monitor and Gateway, with committed cassettes.

No network and no API key: every stream below is replayed from `packages/world/fixtures/cassettes`.
The committed cassettes are scripted (model `scripted-v1`): their keys are real prompt hashes, so
the replay is real, but the responses were written by `notary_server.recording`, not by a model.
"""

import threading
import time
from collections.abc import Callable, Mapping, Sequence

import pytest
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketTestSession
from starlette.websockets import WebSocketDisconnect

from notary_core.audit import append, verify_chain_detailed
from notary_core.gateway import ToolResultField, make_labeler
from notary_core.models import (
    ArenaStartCommand,
    AuditEntry,
    DecisionMade,
    EffectExecuted,
    EndorsementDecisionCommand,
    EndorsementRequested,
    Event,
    Lane,
    OracleUpdated,
    RunFinished,
)
from notary_core.pinning import ToolManifest
from notary_core.resolver import ArgumentResolver
from notary_mcp_proxy.backend import BackendEffect, BackendRecord, BackendResult
from notary_mcp_proxy.gateway import Gateway, RawCall
from notary_server.agent_runner import EscalationDecider
from notary_server.anchors import AnchorStore
from notary_server.app import create_app
from notary_server.arena import ArenaService
from notary_server.compiler import compile_contract
from notary_server.endorsement import EndorsementBroker
from notary_server.lanes import LANES
from notary_server.llm import (
    CassetteClient,
    LlmClient,
    LlmRequest,
    ScriptedClient,
    cassette_json,
    prompt_text,
)
from notary_server.recording import (
    ARENA_ROUNDS,
    BILL_REQUEST,
    SAMPLE_POISON,
    SCRIPTED_MODEL,
    agent_variants,
    scripted_agent_turns,
    scripted_cassettes,
)
from notary_server.sources import RunMode, RunRequest, RunSource
from notary_server.wiring import (
    CassetteSource,
    LiveSource,
    RunStreamer,
    Settings,
    build_app,
)
from notary_world.attacks import KNOWN_REAL_MONITOR_DEVIATIONS
from notary_world.cassette import cassette_key
from notary_world.cast import ATTACKER_IBAN, BILLER_IBAN
from notary_world.executor import default_monitor, execute_run
from notary_world.golden import COMMAND_ADAPTER, EVENT_ADAPTER, golden_streams, sample_commands
from notary_world.labeling import world_labeling_policy
from notary_world.loader import FIXTURES_DIR, load_cassette
from notary_world.models import Cassette
from notary_world.scenarios import Scenario, get_scenario, golden_run_id
from notary_world.state import diff, seed_world
from notary_world.tools import (
    TOOL_SPECS,
    call,
    default_manifest_hash,
    tool_manifest_hash,
    world_manifests,
    world_policy,
)

assert KNOWN_REAL_MONITOR_DEVIATIONS == {}, "CP1 left no known deviations; CP2 builds on that"

SHORT_TIMEOUT = 0.05
POISONED = "poisoned_bill"


def app_client(timeout: float = SHORT_TIMEOUT) -> TestClient:
    settings = Settings(endorsement_timeout_seconds=timeout)
    return TestClient(build_app(settings, event_delay=0))


def replay(
    client: TestClient, scenario: str, lane: Lane, mode: str = "cassette"
) -> tuple[list[Event], WebSocketDisconnect]:
    events: list[Event] = []
    with client.websocket_connect(f"/ws/runs/{scenario}?lane={lane}&mode={mode}") as ws:
        while True:
            try:
                events.append(EVENT_ADAPTER.validate_json(ws.receive_text()))
            except WebSocketDisconnect as closed:
                return events, closed


def lane_named(name: str) -> Lane:
    for lane in LANES:
        if lane == name:
            return lane
    raise ValueError(name)


def lines(events: Sequence[Event]) -> list[str]:
    return [e.model_dump_json() for e in events]


def chain_of(events: Sequence[Event]) -> tuple[AuditEntry, ...]:
    chain: tuple[AuditEntry, ...] = ()
    for event in events:
        chain = append(chain, event)
    return chain


def decision_for(events: Sequence[Event], call_id: str) -> DecisionMade:
    return next(e for e in events if isinstance(e, DecisionMade) and e.call_id == call_id)


def last_oracle(events: Sequence[Event]) -> OracleUpdated:
    return [e for e in events if isinstance(e, OracleUpdated)][-1]


def collapsed(events: Sequence[Event]) -> list[str]:
    out: list[str] = []
    for event in events:
        if event.type == "value_labeled" and out and out[-1] == "value_labeled":
            continue
        out.append(event.type)
    return out


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("lane", LANES)
def test_cassette_replay_is_byte_identical_on_every_lane(lane: Lane) -> None:
    client = app_client()
    first, closed = replay(client, POISONED, lane)
    second, _ = replay(client, POISONED, lane)
    fresh, _ = replay(app_client(), POISONED, lane)
    assert closed.code == 1000
    assert first
    assert lines(first) == lines(second) == lines(fresh)


@pytest.mark.attack("A3")
def test_notary_blocks_the_swapped_iban() -> None:
    events, _ = replay(app_client(), POISONED, "notary")
    pay = decision_for(events, "c2")
    # Since #119 the payee floor is `endorse`: a novel payee escalates instead of blocking, and
    # nobody approved it here (the decider times out), so the payment never ran.
    assert pay.decision.verdict == "ESCALATE"
    assert "LEDGER_NOVEL_ESCALATE" in [r.code for r in pay.decision.reasons]
    assert any(isinstance(e, EndorsementRequested) for e in events)
    assert not any(isinstance(e, EffectExecuted) and e.call_id == "c2" for e in events)
    assert last_oracle(events).result.attacker_goal_reached is False
    assert last_oracle(events).result.user_goal_achieved is False


@pytest.mark.attack("A3")
@pytest.mark.parametrize("lane", ["undefended", "classifier"])
def test_baselines_lose_the_money(lane: Lane) -> None:
    events, _ = replay(app_client(), POISONED, lane)
    transfers = [e for e in events if isinstance(e, EffectExecuted) and e.tool == "pay_bill"]
    assert len(transfers) == 1
    assert ATTACKER_IBAN in transfers[0].summary
    assert last_oracle(events).result.attacker_goal_reached is True


@pytest.mark.attack("A14")
def test_legitimate_bill_pays_silently() -> None:
    events, _ = replay(app_client(), "legitimate_bill", "notary")
    pay = decision_for(events, "c2")
    assert pay.decision.verdict == "ALLOW"
    assert "LEDGER_EXACT_MATCH" in [r.code for r in pay.decision.reasons]
    assert not any(isinstance(e, EndorsementRequested) for e in events)
    assert any(isinstance(e, EffectExecuted) and e.tool == "pay_bill" for e in events)
    assert last_oracle(events).result.user_goal_achieved is True
    assert last_oracle(events).result.attacker_goal_reached is False


@pytest.mark.invariant("I6")
def test_streams_validate_and_match_golden_shapes() -> None:
    client = app_client()
    streams = golden_streams()
    for name, golden in streams.items():
        scenario, lane = name.split(".")
        events, closed = replay(client, scenario, lane_named(lane))
        assert closed.code == 1000
        assert [e.seq for e in events] == list(range(len(events)))
        assert len({e.run_id for e in events}) == 1
        assert {e.lane for e in events} == {lane}
        assert events[0].run_id == golden[0].run_id
        if lane == "notary":
            # The real Gateway labels every field of the inbox; the hand-built golden shows two.
            assert collapsed(events) == collapsed(golden), name
        else:
            assert [e.type for e in events] == [e.type for e in golden], name


@pytest.mark.invariant("I1")
def test_audit_chain_and_anchor() -> None:
    client = app_client()
    events, _ = replay(client, POISONED, "notary")
    chain = chain_of(events)
    anchor = client.get(f"/runs/{events[0].run_id}/anchor").json()
    assert anchor == {"run_id": events[0].run_id, "head": chain[-1].hash, "length": len(chain)}
    result = verify_chain_detailed(
        chain, expected_length=anchor["length"], expected_head=anchor["head"]
    )
    assert result.ok
    truncated = verify_chain_detailed(
        chain[:-1], expected_length=anchor["length"], expected_head=anchor["head"]
    )
    assert (truncated.ok, truncated.reason) == (False, "length mismatch")
    # A second replay under the same run id restarts the anchor instead of failing.
    again, _ = replay(client, POISONED, "notary")
    assert again[-1].type == "run_finished"
    assert client.get(f"/runs/{events[0].run_id}/anchor").json() == anchor


class TrackingClient:
    """A cassette replay that remembers which entries were asked for."""

    def __init__(self, name: str) -> None:
        self._cassette = load_cassette(name)
        self._inner = CassetteClient(self._cassette)
        self.used: set[str] = set()

    @property
    def keys(self) -> set[str]:
        return {entry.key for entry in self._cassette.entries}

    def complete(self, request: LlmRequest):
        self.used.add(cassette_key(self._cassette.lane, prompt_text(request)))
        return self._inner.complete(request)


def streamer() -> RunStreamer:
    return RunStreamer(
        broker=EndorsementBroker(timeout_seconds=SHORT_TIMEOUT), anchors=AnchorStore()
    )


@pytest.mark.invariant("I6")
def test_every_cassette_replays_without_a_miss() -> None:
    from notary_server.agent_runner import reject_all
    from notary_server.recording import approve_all, use_nearest_all

    names = sorted(path.stem for path in (FIXTURES_DIR / "cassettes").glob("*.json"))
    assert names == sorted(
        [
            *agent_variants(),
            *(f"arena.{lane}" for lane in LANES),
            "compile.legitimate_bill",
            "compile.poisoned_bill",
        ]
    )
    for name, variants in agent_variants().items():
        client = TrackingClient(name)
        lane = load_cassette(name).lane
        for variant in variants:
            run_id = golden_run_id(variant.scenario.scenario_id, lane)
            decide = {
                "approve": approve_all,
                "reject": reject_all,
                "use_nearest": use_nearest_all,
            }[variant.answer]
            for _ in streamer().stream(variant.scenario, lane, run_id, client, decide):
                pass
        assert client.used == client.keys, name
    for lane in LANES:
        attacker = TrackingClient(f"arena.{lane}")
        service = ArenaService(
            streamer().lane_runner(),
            lambda _lane, tracking=attacker: tracking,
            max_rounds=ARENA_ROUNDS,
        )
        service.run(
            ArenaStartCommand(
                type="arena_start", scenario=POISONED, rounds=ARENA_ROUNDS, lanes=(lane,), seed=0
            )
        )
        assert attacker.used == attacker.keys, lane
    for scenario_id in ("legitimate_bill", "poisoned_bill"):
        compiler = TrackingClient(f"compile.{scenario_id}")
        compile_contract(
            BILL_REQUEST, world_manifests(seed_world(0)), compiler, policy=world_policy()
        )
        assert compiler.used == compiler.keys


@pytest.mark.invariant("I6")
def test_committed_scripted_cassettes_are_current() -> None:
    """Fails when a prompt changed: re-run `scripts/record_cassettes.py` (scripted or --live)."""
    committed = {
        path.stem: path.read_text(encoding="utf-8")
        for path in (FIXTURES_DIR / "cassettes").glob("*.json")
    }
    if any(load_cassette(name).model != SCRIPTED_MODEL for name in committed):
        pytest.skip("cassettes were recorded live; they are checked by replay, not regenerated")
    fresh = {name: cassette_json(c) for name, c in scripted_cassettes().items()}
    assert committed == fresh


@pytest.mark.invariant("I6")
def test_cassette_miss_is_an_error_not_a_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    real = load_cassette("poisoned_bill.notary")
    changed = real.model_copy(
        update={
            "entries": tuple(
                e.model_copy(update={"key": f"{i:064x}"}) if i > 0 else e
                for i, e in enumerate(real.entries)
            )
        }
    )

    def altered(_name: str) -> Cassette:
        return changed

    monkeypatch.setattr("notary_server.wiring.load_cassette", altered)
    events, closed = replay(app_client(), POISONED, "notary")
    assert (closed.code, closed.reason) == (4502, "cassette miss")
    assert lines(events) != lines(golden_streams()["poisoned_bill.notary"])
    assert events[-1].type != "run_finished"


@pytest.mark.invariant("I6")
def test_a_missing_cassette_and_an_unknown_scenario_are_errors() -> None:
    client = app_client()
    missing, closed = replay(client, "legitimate_bill", "undefended")
    assert (missing, closed.code, closed.reason) == ([], 4502, "cassette not found")
    unknown, closed = replay(client, "nope", "notary")
    assert (unknown, closed.code, closed.reason) == ([], 4404, "unknown scenario")


class RecordingEnviron(Mapping[str, str]):
    """An environment that remembers which names were read."""

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)
        self.read: set[str] = set()

    def __getitem__(self, key: str) -> str:
        self.read.add(key)
        return self._values[key]

    def __iter__(self):
        raise AssertionError("the environment must not be enumerated")

    def __len__(self) -> int:
        raise AssertionError("the environment must not be enumerated")


@pytest.mark.invariant("I6")
def test_live_mode_needs_a_key() -> None:
    environ = RecordingEnviron({"HOME": "/home/x", "NOTARY_ARENA_MAX_ROUNDS": "4"})
    settings = Settings.from_env(environ)
    assert settings.live_available is False
    assert environ.read <= {
        "ANTHROPIC_API_KEY",
        "NOTARY_ANCHOR_DB",
        "NOTARY_ENDORSEMENT_TIMEOUT",
        "NOTARY_ARENA_MAX_ROUNDS",
    }
    client = TestClient(build_app(settings, event_delay=0))
    events, closed = replay(client, POISONED, "notary", mode="live")
    assert (events, closed.code, closed.reason) == ([], 4501, "mode not available")
    assert client.get("/runs/modes").json() == {"modes": ["cassette", "golden", "live"]}


@pytest.mark.invariant("I6")
def test_the_live_client_is_built_on_the_first_live_request_only() -> None:
    built: list[LlmClient] = []
    scenario = get_scenario(POISONED)

    def factory() -> LlmClient:
        client = ScriptedClient(scripted_agent_turns(scenario))
        built.append(client)
        return client

    source = LiveSource(streamer(), available=True, client_factory=factory)
    assert built == []
    events = list(source.events(RunRequest(scenario=POISONED, lane="undefended", mode="live")))
    assert events[-1].type == "run_finished"
    assert len(built) == 1


@pytest.mark.invariant("I6")
def test_settings_from_env() -> None:
    defaults = Settings.from_env({})
    assert (defaults.anchor_db, defaults.endorsement_timeout_seconds) == (":memory:", 300.0)
    assert (defaults.arena_max_rounds, defaults.live_available) == (10, False)
    custom = Settings.from_env(
        {
            "NOTARY_ANCHOR_DB": "/var/lib/notary/anchors.sqlite",
            "NOTARY_ENDORSEMENT_TIMEOUT": "2.5",
            "NOTARY_ARENA_MAX_ROUNDS": "25",
            "ANTHROPIC_API_KEY": "sk-not-stored",
        }
    )
    assert custom.anchor_db == "/var/lib/notary/anchors.sqlite"
    assert (custom.endorsement_timeout_seconds, custom.arena_max_rounds) == (2.5, 25)
    assert custom.live_available is True
    assert "sk-not-stored" not in custom.model_dump_json()
    bad: list[dict[str, str]] = [
        {"NOTARY_ENDORSEMENT_TIMEOUT": "soon"},
        {"NOTARY_ENDORSEMENT_TIMEOUT": "0"},
        {"NOTARY_ENDORSEMENT_TIMEOUT": "-3"},
        {"NOTARY_ENDORSEMENT_TIMEOUT": "nan"},
        {"NOTARY_ENDORSEMENT_TIMEOUT": "inf"},
        {"NOTARY_ARENA_MAX_ROUNDS": "many"},
        {"NOTARY_ARENA_MAX_ROUNDS": "0"},
        {"NOTARY_ARENA_MAX_ROUNDS": "1.5"},
        {"NOTARY_ARENA_MAX_ROUNDS": "101"},
        {"NOTARY_ANCHOR_DB": ""},
    ]
    for environ in bad:
        with pytest.raises(ValueError):  # noqa: PT011 - the message is the variable's name
            Settings.from_env(environ)


@pytest.mark.attack("A10")
def test_compiled_contract_matches_the_engines_manifest_hashes() -> None:
    compiled = compile_contract(
        BILL_REQUEST,
        world_manifests(seed_world(0)),
        CassetteClient(load_cassette("compile.poisoned_bill")),
        policy=world_policy(),
    )
    scopes = {scope.tool: scope for scope in compiled.contract.allowed_tools}
    assert set(scopes) == {"read_inbox", "pay_bill"}
    world = seed_world(0)
    for tool, scope in scopes.items():
        assert scope.manifest_hash == default_manifest_hash(tool) == tool_manifest_hash(world, tool)
    # What the engine stamps on a live proposal is the pinned value, so step 1 passes.
    events, _ = replay(app_client(), POISONED, "notary")
    stamped = {
        e.proposal.tool: e.proposal.manifest_hash for e in events if e.type == "call_proposed"
    }
    assert stamped == {tool: scope.manifest_hash for tool, scope in scopes.items()}
    assert {s.name for s in TOOL_SPECS} >= set(scopes)


class WorldBackend:
    """The adapter's tool backend over the seeded world (what an MCP server would be)."""

    def __init__(self, scenario: Scenario) -> None:
        self.world = scenario.world

    def list_tools(self) -> Sequence[ToolManifest]:
        return world_manifests(self.world)

    def call_tool(self, tool: str, args: Mapping[str, str]) -> BackendResult:
        result = call(self.world, tool, args)
        if result.error is not None:
            return BackendResult(records=(), effect=None, error=result.error)
        self.world = result.new_state
        records = tuple(
            BackendRecord(
                record_id=record.record_id,
                readers=record.readers,
                fields=tuple(
                    ToolResultField(name=f.name, text=f.text, unit=f.unit) for f in record.fields
                ),
            )
            for record in result.records
        )
        effect = result.effect
        return BackendResult(
            records=records,
            effect=None
            if effect is None
            else BackendEffect(
                summary=effect.summary,
                spent_cents=effect.spent_cents,
                egress_bytes=effect.egress_bytes,
                mutating=effect.effect != "read",
            ),
            error=None,
        )


@pytest.mark.invariant("I1")
@pytest.mark.parametrize("scenario_id", ["legitimate_bill", "poisoned_bill"])
def test_adapter_agrees_with_the_engine(scenario_id: str) -> None:
    scenario = get_scenario(scenario_id)
    record = execute_run(
        scenario=scenario.scenario_id,
        run_id="run-engine",
        request=scenario.user_request,
        world=scenario.world,
        contract=scenario.contract,
        ledger=scenario.ledger,
        session=scenario.session,
        calls=scenario.calls,
    )
    backend = WorldBackend(scenario)
    gateway = Gateway(
        backend=backend,
        contract=scenario.contract,
        ledger=scenario.ledger,
        monitor=default_monitor(),
        labeler=make_labeler(world_labeling_policy()),
        resolver=ArgumentResolver(),
        run_id="run-adapter",
        policy=world_policy(),
        session=scenario.session,
    )
    gateway.pin_session()
    outcomes = [
        gateway.propose(RawCall(call_id=c.call_id, tool=c.tool, args=dict(c.args)))
        for c in scenario.calls
    ]
    for engine_call, outcome in zip(record.calls, outcomes, strict=True):
        assert outcome.decision is not None
        assert outcome.decision.verdict == engine_call.decision.verdict
        assert [r.code for r in outcome.decision.reasons] == [
            r.code for r in engine_call.decision.reasons
        ]
        assert outcome.status == engine_call.status or outcome.status == "escalated"
    assert diff(scenario.world, backend.world) == record.world_diff
    assert gateway.session == record.session


@pytest.mark.attack("A3")
def test_playground_and_hijacked_routes_use_the_real_runner() -> None:
    client = app_client()
    command = COMMAND_ADAPTER.dump_python(sample_commands()["poison_world"], mode="json")
    assert command["payload"] == SAMPLE_POISON.payload
    poisoned = client.post("/playground/poison", json=command)
    assert poisoned.status_code == 200
    runs = poisoned.json()["runs"]
    assert [run["lane"] for run in runs] == ["undefended", "classifier", "notary"]
    assert [run["attacker_goal_reached"] for run in runs] == [True, True, False]
    session = client.post("/playground/hijacked", json={"scenario": "legitimate_bill", "seed": 0})
    session_id = session.json()["session_id"]
    attack = client.post(
        f"/playground/hijacked/{session_id}/calls",
        json={
            "type": "hijacked_tool_call",
            "run_id": session.json()["run_id"],
            "call_id": "c1",
            "tool": "pay_bill",
            "args": {"payee": ATTACKER_IBAN, "amount": "120.00"},
        },
    )
    assert attack.json()["status"] in {"blocked", "escalated"}
    assert attack.json()["oracle"]["attacker_goal_reached"] is False


@pytest.mark.attack("A3")
def test_arena_replays_through_the_same_runner() -> None:
    client = app_client()
    response = client.post(
        "/playground/arena",
        json={
            "type": "arena_start",
            "scenario": POISONED,
            "rounds": 3,
            "lanes": ["classifier", "notary"],
            "seed": 0,
        },
    )
    assert response.status_code == 200
    by_lane = {lane["lane"]: lane for lane in response.json()["lanes"]}
    assert [r["attacker_goal_reached"] for r in by_lane["classifier"]["rounds"]] == [True] * 3
    assert [r["attacker_goal_reached"] for r in by_lane["notary"]["rounds"]] == [False] * 3


def wait_until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + 5.0
    while not condition():
        assert time.monotonic() < deadline, "condition not reached"
        time.sleep(0.005)


def read_until(ws: WebSocketTestSession, event_type: str) -> list[Event]:
    seen: list[Event] = []
    while True:
        event = EVENT_ADAPTER.validate_json(ws.receive_text())
        seen.append(event)
        if event.type == event_type:
            return seen


def run_to_the_end_with_approval(
    client: TestClient, *, golden: Callable[[TestClient], None] | None = None
) -> list[Event]:
    """Run poisoned_bill / notary in cassette mode, approve its card, and return every event.

    `golden` runs while the card is pending, after the cassette socket stopped at it.
    """
    run_id = golden_run_id(POISONED, "notary")

    def pending() -> int:
        return len(client.get(f"/runs/{run_id}/endorsements").json()["pending"])

    with client.websocket_connect(f"/ws/runs/{POISONED}?lane=notary&mode=cassette") as ws:
        before = read_until(ws, "endorsement_requested")
        assert len(before) == 18
        wait_until(lambda: pending() == 1)
        if golden is not None:
            golden(client)
            assert pending() == 1
        card = next(e for e in reversed(before) if isinstance(e, EndorsementRequested))
        command = EndorsementDecisionCommand(
            type="endorsement_decision",
            run_id=run_id,
            endorsement_id=card.endorsement.endorsement_id,
            decision="approve",
        )
        ws.send_text(COMMAND_ADAPTER.dump_json(command).decode("utf-8"))
        after: list[Event] = []
        while True:
            try:
                after.append(EVENT_ADAPTER.validate_json(ws.receive_text()))
            except WebSocketDisconnect:
                break
    return [*before, *after]


def golden_runs_to_the_end(client: TestClient) -> None:
    for lane in ("notary", "undefended"):
        _events, closed = replay(client, POISONED, lane_named(lane), mode="golden")
        assert closed.code == 1000


def golden_run_abandoned(client: TestClient) -> None:
    """A golden socket the browser closes after the first frame."""
    with client.websocket_connect(f"/ws/runs/{POISONED}?lane=notary&mode=golden") as ws:
        ws.receive_text()


@pytest.mark.invariant("I4")
@pytest.mark.parametrize(
    "golden",
    [golden_runs_to_the_end, golden_run_abandoned],
    ids=["golden-finishes", "golden-abandoned"],
)
def test_closing_a_golden_socket_leaves_a_pending_cassette_card_alone(
    golden: Callable[[TestClient], None],
) -> None:
    """Golden and cassette runs share `run-poisoned_bill-notary` (#194). A golden socket closing
    must not reject the cassette run's card: it stays pending, answerable, and the cassette stream
    is byte-identical to the run without a golden socket."""
    alone = run_to_the_end_with_approval(app_client(timeout=5.0))
    beside_golden = run_to_the_end_with_approval(app_client(timeout=5.0), golden=golden)
    assert lines(beside_golden) == lines(alone)
    pay_decisions = [e for e in beside_golden if isinstance(e, DecisionMade) and e.call_id == "c2"]
    assert [d.decision.verdict for d in pay_decisions] == ["ESCALATE", "ALLOW"]


class SpyBroker(EndorsementBroker):
    def __init__(self) -> None:
        super().__init__(timeout_seconds=5.0)
        self.calls: list[str] = []

    def decider_for(self, run_id: str, *, owner: str, max_approvals: int) -> EscalationDecider:
        self.calls.append("decider_for")
        return super().decider_for(run_id, owner=owner, max_approvals=max_approvals)

    def cancel_run(self, run_id: str, *, owner: str) -> None:
        self.calls.append("cancel_run")
        super().cancel_run(run_id, owner=owner)


@pytest.mark.invariant("I4")
def test_a_golden_run_never_registers_a_card_or_touches_the_broker() -> None:
    """Golden streams contain an `endorsement_requested` event, but it is replayed text: nobody
    waits, so the broker has no card, and no golden socket resets or cancels a run."""
    broker = SpyBroker()
    client = TestClient(create_app(event_delay=0, broker=broker))
    run_id = golden_run_id(POISONED, "notary")
    with client.websocket_connect(f"/ws/runs/{POISONED}?lane=notary&mode=golden") as ws:
        seen = read_until(ws, "endorsement_requested")
        assert any(isinstance(e, EndorsementRequested) for e in seen)
        assert client.get(f"/runs/{run_id}/endorsements").json() == {"pending": []}
        golden_rest = [EVENT_ADAPTER.validate_json(ws.receive_text()) for _ in range(2)]
        assert golden_rest
    golden_run_abandoned(client)  # the path that used to cancel the run id
    assert client.get(f"/runs/{run_id}/endorsements").json() == {"pending": []}
    assert broker.calls == []


@pytest.mark.invariant("I4")
def test_a_closing_cassette_socket_still_rejects_its_own_card() -> None:
    """The mode check keeps the real case: an abandoned cassette run fails closed."""
    broker = SpyBroker()
    streamer = RunStreamer(broker=broker, anchors=AnchorStore(":memory:"))
    sources: dict[RunMode, RunSource] = {"cassette": CassetteSource(streamer)}
    client = TestClient(create_app(event_delay=0, sources=sources, broker=broker))
    run_id = golden_run_id(POISONED, "notary")
    with client.websocket_connect(f"/ws/runs/{POISONED}?lane=notary&mode=cassette") as ws:
        read_until(ws, "endorsement_requested")
        wait_until(lambda: len(broker.pending_for_run(run_id)) == 1)
    wait_until(lambda: broker.pending_for_run(run_id) == ())
    assert "cancel_run" in broker.calls


@pytest.mark.invariant("I4")
def test_the_card_is_listed_when_the_cassette_frame_arrives() -> None:
    """#195: no wait between the `endorsement_requested` frame and the pending list."""
    client = TestClient(build_app(Settings(endorsement_timeout_seconds=5.0), event_delay=0.05))
    run_id = golden_run_id(POISONED, "notary")
    with client.websocket_connect(f"/ws/runs/{POISONED}?lane=notary&mode=cassette") as ws:
        seen = read_until(ws, "endorsement_requested")
        card = next(e for e in reversed(seen) if isinstance(e, EndorsementRequested))
        listed = client.get(f"/runs/{run_id}/endorsements").json()["pending"]
        assert [p["endorsement"]["endorsement_id"] for p in listed] == [
            card.endorsement.endorsement_id
        ]
        assert listed[0]["remaining_approvals"] == 3


@pytest.mark.invariant("I4")
def test_endorsement_flow_over_the_socket() -> None:
    """A determined user can still say yes (A11): the approved payment runs, and only because of
    the command; the engine wrote the endorsed payee to the ledger, so the re-decision is ALLOW
    with an exact ledger match."""
    client = app_client(timeout=5.0)
    run_id = golden_run_id(POISONED, "notary")
    results: list[list[Event]] = []

    def drive() -> None:
        with client.websocket_connect(f"/ws/runs/{POISONED}?lane=notary&mode=cassette") as ws:
            before = read_until(ws, "endorsement_requested")
            wait_until(
                lambda: len(client.get(f"/runs/{run_id}/endorsements").json()["pending"]) == 1
            )
            card = next(e for e in reversed(before) if isinstance(e, EndorsementRequested))
            command = EndorsementDecisionCommand(
                type="endorsement_decision",
                run_id=run_id,
                endorsement_id=card.endorsement.endorsement_id,
                decision="approve",
            )
            ws.send_text(COMMAND_ADAPTER.dump_json(command).decode("utf-8"))
            after: list[Event] = []
            while True:
                try:
                    after.append(EVENT_ADAPTER.validate_json(ws.receive_text()))
                except WebSocketDisconnect:
                    break
            results.append([*before, *after])

    thread = threading.Thread(target=drive)
    thread.start()
    thread.join(30)
    assert not thread.is_alive()
    (events,) = results
    pay_decisions = [e for e in events if isinstance(e, DecisionMade) and e.call_id == "c2"]
    assert [d.decision.verdict for d in pay_decisions] == ["ESCALATE", "ALLOW"]
    assert "LEDGER_EXACT_MATCH" in [r.code for r in pay_decisions[1].decision.reasons]
    assert any(isinstance(e, EffectExecuted) and e.tool == "pay_bill" for e in events)
    assert BILLER_IBAN not in lines(events)[-1]
    assert client.get(f"/runs/{run_id}/endorsements").json() == {"pending": []}


@pytest.mark.attack("A3")
@pytest.mark.invariant("I4")
def test_use_nearest_pays_the_known_payee_and_writes_nothing_to_the_ledger() -> None:
    """The user answers the card with the nearest known payee instead of the swapped one: the
    swapped IBAN is not paid, a new call is proposed with the ledger's value and judged by the
    monitor like any other, and the run ends with both goals met (#207)."""
    client = app_client(timeout=5.0)
    run_id = golden_run_id(POISONED, "notary")
    results: list[list[Event]] = []

    def drive() -> None:
        with client.websocket_connect(f"/ws/runs/{POISONED}?lane=notary&mode=cassette") as ws:
            before = read_until(ws, "endorsement_requested")
            wait_until(
                lambda: len(client.get(f"/runs/{run_id}/endorsements").json()["pending"]) == 1
            )
            card = next(e for e in reversed(before) if isinstance(e, EndorsementRequested))
            command = EndorsementDecisionCommand(
                type="endorsement_decision",
                run_id=run_id,
                endorsement_id=card.endorsement.endorsement_id,
                decision="use_nearest",
            )
            ws.send_text(COMMAND_ADAPTER.dump_json(command).decode("utf-8"))
            after: list[Event] = []
            while True:
                try:
                    after.append(EVENT_ADAPTER.validate_json(ws.receive_text()))
                except WebSocketDisconnect:
                    break
            results.append([*before, *after])

    thread = threading.Thread(target=drive)
    thread.start()
    thread.join(30)
    assert not thread.is_alive()
    (events,) = results
    assert [d.decision.verdict for d in events if isinstance(d, DecisionMade)] == [
        "ALLOW",
        "ESCALATE",
        "ALLOW",
    ]
    replacement = decision_for(events, "c2.nearest")
    assert replacement.decision.verdict == "ALLOW"
    assert "LEDGER_EXACT_MATCH" in [r.code for r in replacement.decision.reasons]
    paid = [e for e in events if isinstance(e, EffectExecuted) and e.tool == "pay_bill"]
    assert [e.call_id for e in paid] == ["c2.nearest"]
    assert BILLER_IBAN in paid[0].summary
    assert ATTACKER_IBAN not in paid[0].summary
    assert not any(isinstance(e, EffectExecuted) and e.call_id == "c2" for e in events)
    oracle = last_oracle(events).result
    assert oracle.attacker_goal_reached is False
    assert oracle.user_goal_achieved is True
    assert all(i.passed for i in oracle.invariants)
    finished = [e for e in events if isinstance(e, RunFinished)][-1]
    assert (finished.outcome, finished.summary) == ("completed", "all calls executed")
    assert client.get(f"/runs/{run_id}/endorsements").json() == {"pending": []}
