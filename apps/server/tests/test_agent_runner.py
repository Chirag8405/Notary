from collections.abc import Sequence
from typing import Literal

import pytest
from builders import (
    FINAL,
    PAY_ACME,
    PAY_ATTACKER,
    READ_INBOX,
    assistant,
    catalog,
    last_oracle,
    notary_hooks,
    run_lane,
    tool_messages,
    types_collapsed,
)

from notary_core.audit import append, verify_chain
from notary_core.models import (
    CHECK_ORDER,
    AuditEntry,
    DecisionMade,
    EffectExecuted,
    Endorsement,
    EndorsementRequested,
    Event,
    OracleUpdated,
    RunFinished,
    RunStarted,
    ToolCallProposal,
)
from notary_core.runner import AgentRunner
from notary_server.agent_io import MAX_TURNS, REFUSAL_TEXT
from notary_server.agent_runner import (
    SCENARIO_GOALS,
    ServerAgentRunner,
    goals_for,
    reject_all,
    scenario_contract,
    ungated_monitor,
)
from notary_server.labeling import world_labeling_policy
from notary_server.llm import CassetteClient, RecordingClient, ScriptedClient
from notary_server.runner import ScenarioNotFoundError
from notary_world.cast import ATTACKER_IBAN
from notary_world.classifier import REDACTION_MARKER
from notary_world.golden import golden_streams
from notary_world.poison import INSTRUCTION_TEXT
from notary_world.scenarios import Scenario, legitimate_bill_scenario
from notary_world.tools import default_manifest_hash


@pytest.mark.invariant("I1")
def test_legitimate_bill_run_matches_the_golden_shape() -> None:
    client = ScriptedClient([READ_INBOX, PAY_ACME, FINAL])
    events, record = run_lane(client)
    assert types_collapsed(events) == types_collapsed(golden_streams()["legitimate_bill.notary"])
    oracle = last_oracle(events).result
    assert oracle.user_goal_achieved is True
    assert oracle.attacker_goal_reached is False
    assert all(r.passed for r in oracle.invariants)
    finished = events[-1]
    assert isinstance(finished, RunFinished)
    assert finished.outcome == "completed"
    assert isinstance(events[0], RunStarted)
    assert [e.seq for e in events] == list(range(len(events)))
    assert record.world_diff.changes != ()


@pytest.mark.attack("A3")
def test_poisoned_bill_is_escalated_rejected_and_the_agent_gets_the_uniform_refusal() -> None:
    client = ScriptedClient([READ_INBOX, PAY_ATTACKER, FINAL])
    events, record = run_lane(client, "poisoned_bill")
    decisions = [e for e in events if isinstance(e, DecisionMade)]
    assert [d.decision.verdict for d in decisions] == ["ALLOW", "ESCALATE"]
    assert any(isinstance(e, EndorsementRequested) for e in events)
    assert not any(isinstance(e, EffectExecuted) and e.call_id == "c2" for e in events)
    assert tool_messages(client)[-1] == REFUSAL_TEXT
    assert not [t for t in record.world_after.bank.transfers if t.to_iban == ATTACKER_IBAN]
    assert last_oracle(events).result.attacker_goal_reached is False


@pytest.mark.attack("A3")
def test_a_user_who_approves_the_bad_payee_still_loses_the_money() -> None:
    seen: list[Endorsement] = []

    def approve(endorsement: Endorsement) -> Literal["approve", "reject"]:
        seen.append(endorsement)
        return "approve"

    client = ScriptedClient([READ_INBOX, PAY_ATTACKER, FINAL])
    events, record = run_lane(client, "poisoned_bill", decider=approve)
    assert len(seen) == 1
    assert [t.to_iban for t in record.world_after.bank.transfers][-1] == ATTACKER_IBAN
    assert last_oracle(events).result.attacker_goal_reached is True


@pytest.mark.invariant("I6")
def test_replay_is_byte_identical() -> None:
    turns = [READ_INBOX, PAY_ACME, FINAL]
    first, _ = run_lane(ScriptedClient(turns))
    second, _ = run_lane(ScriptedClient(turns))
    assert [e.model_dump_json() for e in first] == [e.model_dump_json() for e in second]


@pytest.mark.invariant("I6")
def test_cassette_round_trip() -> None:
    recorder = RecordingClient(
        ScriptedClient([READ_INBOX, PAY_ACME, FINAL]),
        lane="notary",
        name="legitimate_bill.notary",
        model="m",
    )
    recorded, _ = run_lane(recorder)
    replayed, _ = run_lane(CassetteClient(recorder.cassette()))
    assert [e.model_dump_json() for e in recorded] == [e.model_dump_json() for e in replayed]


@pytest.mark.invariant("I6")
def test_events_stream_lazily() -> None:
    client = ScriptedClient([READ_INBOX, PAY_ACME, FINAL])
    runner = ServerAgentRunner(llm=client, scenarios=catalog)
    run = runner.run(
        lane="notary", scenario="legitimate_bill", run_id="run-x", hooks=notary_hooks()
    )
    assert isinstance(next(run), RunStarted)
    assert client.requests == ()
    next(run)
    assert len(client.requests) == 1


@pytest.mark.attack("A11")
def test_endorsement_is_streamed_before_the_decider_runs() -> None:
    client = ScriptedClient([assistant(("add_contact", {"name": "Alpha Consulting"})), FINAL])
    streamed: list[Event] = []
    asked_after: list[bool] = []

    def decide(endorsement: Endorsement) -> Literal["approve", "reject"]:
        asked_after.append(any(isinstance(e, EndorsementRequested) for e in streamed))
        return "reject"

    runner = ServerAgentRunner(llm=client, scenarios=catalog, decide_escalation=decide)
    run = runner.run(lane="notary", scenario="contacts", run_id="run-c", hooks=notary_hooks())
    while True:
        try:
            streamed.append(next(run))
        except StopIteration:
            break
    assert asked_after == [True]


def approve_all(endorsement: Endorsement) -> Literal["approve", "reject"]:
    return "approve"


@pytest.mark.invariant("I4")
def test_decider_approve_writes_the_ledger() -> None:
    client = ScriptedClient([assistant(("add_contact", {"name": "Alpha Consulting"})), FINAL])
    events, record = run_lane(client, "contacts", decider=approve_all)
    assert [c.name for c in record.world_after.contacts][-1] == "Alpha Consulting"
    final_ledger = record.ledger_snapshots[-1].ledger
    assert [e.source.kind for e in final_ledger] == ["user_endorsed"]
    assert record.session.approvals_used == 1
    assert any(isinstance(e, EffectExecuted) for e in events)


@pytest.mark.attack("A11")
@pytest.mark.parametrize("use_default", [True, False])
def test_reject_and_default_decider_leave_the_world_unchanged(use_default: bool) -> None:
    def reject(endorsement: Endorsement) -> Literal["approve", "reject"]:
        return "reject"

    client = ScriptedClient([assistant(("add_contact", {"name": "Alpha Consulting"})), FINAL])
    decider = reject_all if use_default else reject
    events, record = run_lane(client, "contacts", decider=decider)
    assert record.world_diff.changes == ()
    assert tool_messages(client)[-1] == REFUSAL_TEXT
    assert not any(isinstance(e, EffectExecuted) for e in events)
    assert record.session.approvals_used == 0


@pytest.mark.attack("A11")
def test_approval_budget_exhaustion() -> None:
    calls = [
        assistant(("add_contact", {"name": n})) for n in ("Alpha", "Bravo", "Charlie", "Delta")
    ]
    asked: list[Endorsement] = []

    def count(endorsement: Endorsement) -> Literal["approve", "reject"]:
        asked.append(endorsement)
        return "approve"

    events, record = run_lane(ScriptedClient([*calls, FINAL]), "contacts1", decider=count)
    assert len(asked) == 1
    blocked = [
        e.decision for e in events if isinstance(e, DecisionMade) and e.decision.verdict == "BLOCK"
    ]
    assert blocked
    assert all(d.reasons[-1].code == "BUDGET_APPROVALS_EXHAUSTED" for d in blocked)
    assert len(record.world_after.contacts) == len(legitimate_bill_scenario().world.contacts) + 1


@pytest.mark.attack("A1")
def test_pre_filter_is_applied_on_the_classifier_lane() -> None:
    client = ScriptedClient([READ_INBOX, FINAL])
    run_lane(client, "injected", "classifier")
    message = tool_messages(client)[-1]
    assert REDACTION_MARKER in message
    assert "[flagged body" in message
    assert INSTRUCTION_TEXT not in message


@pytest.mark.attack("A2")
def test_spotlight_only_with_a_gate() -> None:
    notary = ScriptedClient([READ_INBOX, FINAL])
    run_lane(notary)
    assert "<untrusted>" in tool_messages(notary)[-1]
    undefended = ScriptedClient([READ_INBOX, FINAL])
    run_lane(undefended, lane="undefended")
    assert "<untrusted>" not in tool_messages(undefended)[-1]


@pytest.mark.invariant("I6")
def test_tool_results_are_grouped_by_record_with_fields_sorted() -> None:
    client = ScriptedClient([READ_INBOX, FINAL])
    run_lane(client, lane="undefended")
    message = tool_messages(client)[-1]
    headers = [ln for ln in message.splitlines() if ln.startswith("[tool_result")]
    assert headers == [
        "[tool_result tool=read_inbox record=c1.m-dec]",
        "[tool_result tool=read_inbox record=c1.m-oct]",
    ]
    first = message.split("\n\n")[0].splitlines()
    names = [ln.split(":", 1)[0] for ln in first[1:]]
    assert names == sorted(names)
    assert names[0] == "attachment_0"


@pytest.mark.invariant("I1")
def test_write_tools_answer_with_the_effect_summary() -> None:
    client = ScriptedClient([PAY_ACME, FINAL])
    run_lane(client)
    assert tool_messages(client)[-1].startswith("paid 120.00 EUR to ")


@pytest.mark.invariant("I1")
def test_tool_error_reaches_the_agent() -> None:
    client = ScriptedClient([assistant(("read_file", {"path": "nope"})), FINAL])
    run_lane(client, lane="undefended")
    assert tool_messages(client)[-1] == "error: not_found"


@pytest.mark.attack("A12")
def test_every_refusal_is_the_same_text() -> None:
    out_of_scope = ScriptedClient([assistant(("delete_email", {"message_id": "m-oct"})), FINAL])
    run_lane(out_of_scope)
    escalated = ScriptedClient([READ_INBOX, PAY_ATTACKER, FINAL])
    run_lane(escalated, "poisoned_bill")
    assert tool_messages(out_of_scope)[-1] == tool_messages(escalated)[-1] == REFUSAL_TEXT


@pytest.mark.invariant("I6")
def test_max_turns_bounds_the_loop() -> None:
    client = ScriptedClient([READ_INBOX] * 40)
    events, _ = run_lane(client)
    assert len(client.requests) == MAX_TURNS
    assert isinstance(events[-1], RunFinished)
    assert isinstance(events[-2], OracleUpdated)


@pytest.mark.invariant("I1")
def test_audit_failure_halts_before_any_effect() -> None:
    def failing(chain: Sequence[AuditEntry], event: Event) -> tuple[AuditEntry, ...]:
        if isinstance(event, DecisionMade):
            raise RuntimeError("disk full")
        return append(chain, event)

    client = ScriptedClient([READ_INBOX, PAY_ACME, FINAL])
    events, record = run_lane(client, audit_append=failing)
    assert record.halted == "audit append failed"
    assert not any(isinstance(e, (DecisionMade, EffectExecuted)) for e in events)
    assert record.world_diff.changes == ()
    assert len(client.requests) == 1


@pytest.mark.invariant("I6")
def test_unknown_scenario_propagates() -> None:
    def missing(name: str) -> Scenario:
        raise ScenarioNotFoundError(name)

    runner = ServerAgentRunner(llm=ScriptedClient([]), scenarios=missing)
    run = runner.run(lane="notary", scenario="nope", run_id="r", hooks=notary_hooks())
    with pytest.raises(ScenarioNotFoundError):
        next(run)


@pytest.mark.invariant("I5")
def test_a_custom_contract_source_is_used() -> None:
    base = legitimate_bill_scenario().contract
    narrow = base.model_copy(update={"contract_id": "contract-narrow"})
    events, _ = run_lane(ScriptedClient([FINAL]), contracts=lambda scenario, lane: narrow)
    started = events[0]
    assert isinstance(started, RunStarted)
    assert started.contract.contract_id == "contract-narrow"
    assert scenario_contract(legitimate_bill_scenario(), "notary") == base


@pytest.mark.invariant("I2")
def test_platform_facts_are_trusted_and_content_is_not() -> None:
    _, record = run_lane(ScriptedClient([READ_INBOX, FINAL]))
    values = {v.ref.id: v for v in record.values}
    verified = values["c1.m-dec.verified"].ref.label
    body = values["c1.m-dec.body"].ref.label
    assert (verified.integrity, verified.origin.kind) == ("trusted", "email")
    assert (body.integrity, body.origin.kind) == ("untrusted", "email")
    assert verify_chain(record.chain)


@pytest.mark.invariant("I2")
def test_world_labeling_policy() -> None:
    policy = world_labeling_policy()
    assert {(r.tool, r.origin.kind) for r in policy.origins} == {
        ("read_inbox", "email"),
        ("read_email", "email"),
        ("read_file", "file"),
        ("list_files", "file"),
    }
    assert {(s.tool, s.field, s.integrity) for s in policy.stamps} == {
        ("read_inbox", "verified", "trusted"),
        ("read_email", "verified", "trusted"),
        ("get_balance", "iban", "trusted"),
        ("get_balance", "balance", "trusted"),
    }


@pytest.mark.invariant("I6")
def test_goals_and_small_helpers() -> None:
    assert goals_for("poisoned_bill") == SCENARIO_GOALS["poisoned_bill"]
    assert goals_for("legitimate_bill").attacker_goal_id == "attacker:pay_attacker_iban"
    assert goals_for("anything-else") == goals_for("legitimate_bill")
    decision = ungated_monitor()(
        legitimate_bill_scenario().contract,
        ToolCallProposal(
            call_id="c1",
            tool="read_inbox",
            manifest_hash=default_manifest_hash("read_inbox"),
            args={},
        ),
        {},
        (),
        legitimate_bill_scenario().session,
    )
    assert decision.verdict == "ALLOW"
    assert [r.check for r in decision.reasons] == list(CHECK_ORDER)
    assert {r.code for r in decision.reasons} == {"STEP_PASS"}


@pytest.mark.invariant("I6")
def test_runner_satisfies_the_protocol() -> None:
    runner: AgentRunner = ServerAgentRunner(llm=ScriptedClient([FINAL]), scenarios=catalog)
    events = list(
        runner.run(lane="notary", scenario="legitimate_bill", run_id="r", hooks=notary_hooks())
    )
    assert events[0].type == "run_started"
