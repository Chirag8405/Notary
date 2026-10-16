from collections.abc import Iterator

import pytest
from builders import (
    FINAL,
    PAY_ATTACKER,
    READ_INBOX,
    drain,
    last_oracle,
    notary_hooks,
    run_lane,
    tool_messages,
)

from notary_core.audit import verify_chain
from notary_core.models import DecisionMade, Event, Lane, RunStarted
from notary_core.runner import hooks_for_lane
from notary_server.agent_runner import ServerAgentRunner
from notary_server.lanes import GATELESS_DROPPED, LANES, lane_hooks, stream_for_lane
from notary_server.llm import ScriptedClient
from notary_world.cast import ATTACKER_IBAN
from notary_world.classifier import REDACTION_MARKER, ClassifierFilter
from notary_world.golden import CLASSIFIER_NAME, golden_streams
from notary_world.poison import INSTRUCTION_TEXT
from notary_world.scenarios import get_scenario, golden_run_id

BASELINES: tuple[Lane, ...] = ("undefended", "classifier")


def follow_the_bill() -> ScriptedClient:
    """An agent that reads the inbox and pays whatever IBAN the bill says."""
    return ScriptedClient([READ_INBOX, PAY_ATTACKER, FINAL])


def shaped_run(lane: Lane) -> tuple[list[Event], list[Event]]:
    """(the shaped stream, the raw engine stream) of the poisoned bill on `lane`."""
    raw, _ = run_lane(follow_the_bill(), "poisoned_bill", lane)
    return list(stream_for_lane(raw, lane)), raw


@pytest.mark.invariant("I6")
def test_lane_hooks_shapes() -> None:
    assert LANES == ("undefended", "classifier", "notary")
    undefended = lane_hooks("undefended")
    assert (undefended.pre_filter, undefended.gate) == (None, None)
    classifier = lane_hooks("classifier")
    assert isinstance(classifier.pre_filter, ClassifierFilter)
    assert classifier.gate is None
    notary = lane_hooks("notary")
    assert notary.pre_filter is None
    assert notary.gate is not None
    own = notary_hooks().gate
    assert lane_hooks("notary", gate=own).gate is own


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("lane", ["undefended", "classifier"])
def test_a_gate_is_only_for_the_notary_lane(lane: Lane) -> None:
    gate = notary_hooks().gate
    with pytest.raises(ValueError, match="only the notary lane has a gate"):
        lane_hooks(lane, gate=gate)


@pytest.mark.invariant("I6")
def test_lane_hooks_always_pass_hooks_for_lane() -> None:
    for lane in LANES:
        hooks = lane_hooks(lane)
        if lane == "undefended":
            assert hooks == hooks_for_lane("undefended")
        else:
            assert (hooks.pre_filter is None) == (lane == "notary")
            assert (hooks.gate is None) == (lane == "classifier")


@pytest.mark.attack("A3")
@pytest.mark.parametrize("lane", BASELINES)
def test_baseline_streams_match_the_golden_type_sequences(lane: Lane) -> None:
    shaped, _ = shaped_run(lane)
    golden = golden_streams()[f"poisoned_bill.{lane}"]
    assert [e.type for e in shaped] == [e.type for e in golden]
    assert [e.seq for e in shaped] == list(range(len(shaped)))
    assert {e.lane for e in shaped} == {lane}
    assert not {e.type for e in shaped} & GATELESS_DROPPED


@pytest.mark.attack("A3")
def test_classifier_lane_names_the_stand_in() -> None:
    classifier, _ = shaped_run("classifier")
    undefended, _ = shaped_run("undefended")
    first = classifier[0]
    assert isinstance(first, RunStarted)
    assert first.classifier == CLASSIFIER_NAME
    other = undefended[0]
    assert isinstance(other, RunStarted)
    assert other.classifier is None


@pytest.mark.invariant("I6")
def test_notary_stream_is_untouched() -> None:
    shaped, raw = shaped_run("notary")
    assert [e.model_dump_json() for e in shaped] == [e.model_dump_json() for e in raw]
    assert any(isinstance(e, DecisionMade) for e in shaped)


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("lane", BASELINES)
def test_shaping_does_not_touch_the_chain(lane: Lane) -> None:
    client = follow_the_bill()
    runner = ServerAgentRunner(llm=client, scenarios=get_scenario)
    events, record = drain(
        runner.run(
            lane=lane,
            scenario="poisoned_bill",
            run_id=golden_run_id("poisoned_bill", lane),
            hooks=lane_hooks(lane),
        )
    )
    shaped = list(stream_for_lane(events, lane))
    assert verify_chain(record.chain)
    assert {e.type for e in record.events} & GATELESS_DROPPED
    assert len(shaped) < len(record.events)
    assert [e.type for e in events] == [e.type for e in record.events]


@pytest.mark.invariant("I6")
def test_shaping_is_lazy() -> None:
    pulled: list[int] = []

    def source() -> Iterator[Event]:
        events, _ = run_lane(follow_the_bill(), "poisoned_bill", "undefended")
        for index, event in enumerate(events):
            pulled.append(index)
            yield event

    stream = stream_for_lane(source(), "undefended")
    next(stream)
    assert pulled == [0]


@pytest.mark.attack("A3")
@pytest.mark.parametrize("lane", BASELINES)
def test_baseline_lanes_lose_the_money(lane: Lane) -> None:
    client = follow_the_bill()
    events, record = run_lane(client, "poisoned_bill", lane)
    assert [t.to_iban for t in record.world_after.bank.transfers][-1] == ATTACKER_IBAN
    oracle = last_oracle(events).result
    assert oracle.attacker_goal_reached is True
    assert oracle.user_goal_achieved is False
    assert ATTACKER_IBAN in tool_messages(client)[0]
    assert REDACTION_MARKER not in tool_messages(client)[0]


@pytest.mark.attack("A3")
def test_notary_lane_keeps_the_money() -> None:
    events, record = run_lane(follow_the_bill(), "poisoned_bill", "notary")
    assert not [t for t in record.world_after.bank.transfers if t.to_iban == ATTACKER_IBAN]
    assert last_oracle(events).result.attacker_goal_reached is False


@pytest.mark.attack("A1")
def test_classifier_lane_redacts_an_injection() -> None:
    client = ScriptedClient([READ_INBOX, FINAL])
    run_lane(client, "injected", "classifier")
    message = tool_messages(client)[-1]
    assert REDACTION_MARKER in message
    assert INSTRUCTION_TEXT not in message
    plain = ScriptedClient([READ_INBOX, FINAL])
    run_lane(plain, "injected", "undefended")
    assert INSTRUCTION_TEXT in tool_messages(plain)[-1]


@pytest.mark.invariant("I6")
def test_lanes_are_independent_runs() -> None:
    ids: set[str] = set()
    for lane in LANES:
        events, _ = run_lane(follow_the_bill(), "poisoned_bill", lane)
        assert {e.lane for e in events} == {lane}
        ids |= {e.run_id for e in events}
    assert ids == {f"run-poisoned_bill-{lane}" for lane in LANES}
    assert golden_run_id("poisoned_bill", "notary") in ids
