from itertools import pairwise

import pytest
from pydantic import ValidationError

from notary_core.models import ATTACK_CATEGORY_IDS, CHECK_ORDER
from notary_world.cassette import cassette_key
from notary_world.golden import STREAM_NAMES, golden_streams
from notary_world.loader import (
    FIXTURES_DIR,
    load_attack_fixtures,
    load_attacks,
    load_cassette,
    load_stream,
    load_world,
)
from notary_world.models import AttackFixture


def test_world_fixture_validates() -> None:
    world = load_world()
    assert world.seed == 1337
    assert any(not mail.trusted for mail in world.mail)


def test_attack_library_is_a1_to_a14() -> None:
    attacks = load_attacks()
    assert [a.id for a in attacks] == [f"A{i}" for i in range(1, 15)]
    assert all(ATTACK_CATEGORY_IDS[a.id] == a.category for a in attacks)


def test_every_fixture_covers_its_own_id_and_ends_on_the_case_outcome() -> None:
    for fixture in load_attack_fixtures():
        assert fixture.case.id in fixture.covers
        assert fixture.scripted[-1].expected == fixture.case.expected


def test_only_a13_is_deferred_to_the_output_guard() -> None:
    deferred = [f.case.id for f in load_attack_fixtures() if f.deferred_to is not None]
    assert deferred == ["A13"]


def test_call_ids_are_unique_across_the_library() -> None:
    ids = [c.call_id for f in load_attack_fixtures() for c in f.scripted]
    assert len(ids) == len(set(ids))
    assert all(
        i.startswith(f.case.id + ".")
        for f in load_attack_fixtures()
        for i in (c.call_id for c in f.scripted)
    )


def test_fixture_rejects_expected_outcome_mismatch() -> None:
    fixture = load_attack_fixtures()[0]
    data = fixture.model_dump(mode="json")
    data["case"]["expected"]["verdict"] = "ALLOW"
    with pytest.raises(ValidationError):
        AttackFixture.model_validate_json(__import__("json").dumps(data))


def test_cassettes_are_per_lane_and_keys_differ_by_lane() -> None:
    keys: dict[str, set[str]] = {}
    for lane in ("undefended", "classifier", "notary"):
        cassette = load_cassette(f"poisoned_bill.{lane}")
        assert cassette.lane == lane
        keys[lane] = {e.key for e in cassette.entries}
    assert keys["undefended"].isdisjoint(keys["notary"])
    assert cassette_key("notary", "p") != cassette_key("classifier", "p")


def test_golden_streams_cover_all_three_lanes() -> None:
    lanes = {events[0].lane for events in golden_streams().values()}
    assert lanes == {"undefended", "classifier", "notary"}


def test_golden_streams_are_well_formed() -> None:
    for name, events in golden_streams().items():
        assert [e.seq for e in events] == list(range(len(events))), name
        assert len({e.run_id for e in events}) == 1, name
        assert len({e.lane for e in events}) == 1, name
        assert events[0].type == "run_started"
        assert events[-1].type == "run_finished"
        for event in events:
            if event.type == "decision_made":
                checks = [r.check for r in event.decision.reasons]
                assert all(CHECK_ORDER.index(a) < CHECK_ORDER.index(b) for a, b in pairwise(checks))


def test_notary_stream_uses_every_event_type() -> None:
    types = {e.type for e in golden_streams()["poisoned_bill.notary"]}
    assert types == {
        "run_started", "value_labeled", "call_proposed", "decision_made",
        "endorsement_requested", "endorsement_resolved", "effect_executed", "oracle_updated",
        "run_finished",
    }  # fmt: skip


def test_poisoned_bill_outcomes_per_lane() -> None:
    streams = golden_streams()
    for lane in ("undefended", "classifier"):
        oracle = next(e for e in streams[f"poisoned_bill.{lane}"] if e.type == "oracle_updated")
        assert oracle.result.attacker_goal_reached
        assert not oracle.result.user_goal_achieved
    notary = next(e for e in streams["poisoned_bill.notary"] if e.type == "oracle_updated")
    assert not notary.result.attacker_goal_reached
    legit = next(e for e in streams["legitimate_bill.notary"] if e.type == "oracle_updated")
    assert legit.result.user_goal_achieved
    assert not legit.result.attacker_goal_reached


def test_classifier_lane_names_its_stand_in_classifier() -> None:
    started = golden_streams()["poisoned_bill.classifier"][0]
    assert started.type == "run_started"
    assert started.classifier is not None
    assert "stand-in" in started.classifier


def test_stream_fixtures_on_disk_match_the_generator() -> None:
    for name in STREAM_NAMES:
        assert load_stream(name) == golden_streams()[name]
    assert {p.stem for p in (FIXTURES_DIR / "streams").glob("*.json")} == set(STREAM_NAMES)


def test_command_fixtures_on_disk_parse_and_match_the_generator() -> None:
    from notary_world.golden import COMMAND_ADAPTER, sample_commands

    for name, command in sample_commands().items():
        path = FIXTURES_DIR / "commands" / f"{name}.json"
        assert COMMAND_ADAPTER.validate_json(path.read_text(encoding="utf-8")) == command
