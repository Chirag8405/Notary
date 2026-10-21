from notary_core.gateway import GatewayLabeler, ToolResult, ToolResultField, ValueStore
from notary_core.models import (
    EffectBudget,
    IntentContract,
    SessionState,
    ToolCallProposal,
)
from notary_core.monitor import Monitor
from notary_world.fakes import FakeGateway, FakeMonitor, FakeValueStore, decision_for
from notary_world.loader import load_attack_fixtures

CONTRACT = IntentContract(
    contract_id="c",
    user_intent="x",
    allowed_tools=(),
    budget=EffectBudget(
        max_effects=1,
        max_spend_cents=1,
        max_egress_bytes=0,
        max_call_amount_cents=1,
        max_approvals=1,
    ),
    egress_hosts=(),
    authorized_irreversible=(),
)
SESSION = SessionState(
    spent_cents=0, effects_used=0, egress_bytes_used=0, approvals_used=0, escalations_used=0
)


def test_fake_monitor_satisfies_the_monitor_protocol() -> None:
    monitor: Monitor = FakeMonitor(load_attack_fixtures())
    assert callable(monitor)


def test_fake_monitor_returns_each_fixtures_expected_verdict() -> None:
    fixtures = load_attack_fixtures()
    monitor = FakeMonitor(fixtures)
    for fixture in fixtures:
        for call in fixture.scripted:
            proposal = ToolCallProposal(
                call_id=call.call_id, tool=call.tool, manifest_hash="0" * 64, args={}
            )
            decision = monitor(CONTRACT, proposal, {}, (), SESSION)
            assert decision.verdict == call.expected.verdict, (fixture.case.id, call.call_id)
            if call.expected.deciding_check is not None:
                assert (
                    decision.reasons[-1 if call.expected.verdict == "BLOCK" else 3].check
                    == (call.expected.deciding_check)
                    or call.expected.verdict == "ESCALATE"
                )


def test_unknown_call_id_is_blocked_by_scope() -> None:
    monitor = FakeMonitor(())
    proposal = ToolCallProposal(call_id="zzz", tool="t", manifest_hash="0" * 64, args={})
    decision = monitor(CONTRACT, proposal, {}, (), SESSION)
    assert decision.verdict == "BLOCK"
    assert decision.reasons[0].code == "SCOPE_TOOL_NOT_IN_CONTRACT"


def test_decision_for_builds_valid_decisions_for_every_fixture_outcome() -> None:
    for fixture in load_attack_fixtures():
        for call in fixture.scripted:
            assert decision_for(call.expected).verdict == call.expected.verdict


def test_fake_gateway_labels_every_field_untrusted_with_a_matching_hash() -> None:
    labeler: GatewayLabeler = FakeGateway()
    result = ToolResult(
        tool="read_inbox",
        record_id="m1",
        fields=(ToolResultField(name="iban", text="DE00ACME00000000000001", unit="iban"),),
    )
    (value,) = labeler(result, readers=("user",))
    assert value.ref.label.integrity == "untrusted"
    assert value.ref.label.origin.kind == "email"
    assert value.ref.id == "m1.iban"
    import hashlib

    assert value.ref.content_hash == hashlib.sha256(value.text.encode()).hexdigest()


def test_fake_value_store_is_immutable_and_satisfies_the_protocol() -> None:
    result = ToolResult(
        tool="read_file",
        record_id="f1",
        fields=(ToolResultField(name="body", text="hello", unit=None),),
    )
    (value,) = FakeGateway()(result, readers=("*",))
    empty: ValueStore = FakeValueStore()
    filled = empty.with_values([value])
    assert empty.get("f1.body") is None
    assert filled.get("f1.body") == value
    assert set(filled.as_mapping()) == {"f1.body"}
