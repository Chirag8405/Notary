from pathlib import Path

from pydantic import TypeAdapter

from notary_core.models import CHECK_ORDER, Event
from notary_world.loader import FIXTURES_DIR, load_attacks, load_cassette, load_world
from notary_world.sample_run import poisoned_bill_events


def test_world_fixture_validates() -> None:
    world = load_world()
    assert world.seed == 1337
    assert any(not mail.trusted for mail in world.mail)


def test_attack_library_is_a1_to_a14() -> None:
    attacks = load_attacks()
    assert [a.id for a in attacks] == [f"A{i}" for i in range(1, 15)]


def test_cassette_validates() -> None:
    assert load_cassette("poisoned_bill").turns


def test_sample_run_is_well_formed() -> None:
    events = poisoned_bill_events()
    assert [e.seq for e in events] == list(range(len(events)))
    for event in events:
        if event.type == "decision_made":
            assert tuple(r.check for r in event.decision.reasons) == CHECK_ORDER


def test_event_fixtures_on_disk_parse() -> None:
    adapter: TypeAdapter[Event] = TypeAdapter(Event)
    files = sorted(Path(FIXTURES_DIR, "events").glob("*.json"))
    assert len(files) == len(poisoned_bill_events())
    for file in files:
        adapter.validate_json(file.read_text(encoding="utf-8"))
