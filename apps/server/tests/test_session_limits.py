"""Hijacked Mode sessions expire, are capped per client and have unguessable ids; the playground
POSTs are rate limited per client (#242). Every test uses a fake clock: nothing sleeps."""

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_limits import FakeClock

from notary_core.models import HijackedToolCallCommand
from notary_server.app import create_app
from notary_server.hijacked import (
    MAX_SESSIONS,
    HijackedError,
    HijackedSession,
    HijackedSessions,
    HijackedStart,
    counter_session_ids,
)
from notary_server.wiring import Settings, build_app, build_limits

START = {"scenario": "legitimate_bill", "seed": 0}
POISON = Path(__file__).resolve().parents[3] / "packages/world/fixtures/commands/poison_world.json"
ARENA = {
    "type": "arena_start",
    "scenario": "poisoned_bill",
    "rounds": 1,
    "lanes": ["notary"],
    "seed": 0,
}
BEGIN = HijackedStart(scenario="legitimate_bill", seed=0)


def sessions_with(clock: FakeClock, **options: float) -> HijackedSessions:
    """Counter ids (`h1`, ...), no per-client cap unless given, a long idle time unless given."""
    settings: dict[str, float] = {
        "idle_ttl_seconds": 100.0,
        "max_age_seconds": 10_000.0,
        "max_sessions_per_client": MAX_SESSIONS,
    }
    settings.update(options)
    return HijackedSessions(
        clock=clock,
        new_id=counter_session_ids(),
        idle_ttl_seconds=settings["idle_ttl_seconds"],
        max_age_seconds=settings["max_age_seconds"],
        max_sessions_per_client=int(settings["max_sessions_per_client"]),
    )


def read(session: HijackedSession, call_id: str) -> HijackedToolCallCommand:
    return HijackedToolCallCommand(
        type="hijacked_tool_call",
        run_id=session.run_id,
        call_id=call_id,
        tool="read_inbox",
        args={},
    )


def gone(sessions: HijackedSessions, session: HijackedSession) -> bool:
    try:
        sessions.state(session.session_id)
    except HijackedError as error:
        return (error.status, error.detail) == (404, "unknown session")
    return False


# ------------------------------------------------------------------------------- expiry


@pytest.mark.invariant("I6")
def test_an_idle_session_expires_and_answers_like_an_unknown_one() -> None:
    clock = FakeClock()
    sessions = sessions_with(clock)
    session = sessions.start(BEGIN)
    clock.advance(100)
    assert not gone(sessions, session)  # idle for exactly the TTL: still there
    clock.advance(1)
    assert gone(sessions, session)
    with pytest.raises(HijackedError) as submitted:
        sessions.submit(session.session_id, read(session, "c1"))
    assert (submitted.value.status, submitted.value.detail) == (404, "unknown session")


@pytest.mark.invariant("I6")
def test_an_accepted_call_resets_the_idle_timer_but_a_read_of_the_state_does_not() -> None:
    clock = FakeClock()
    sessions = sessions_with(clock)
    session = sessions.start(BEGIN)
    clock.advance(60)
    sessions.submit(session.session_id, read(session, "c1"))
    clock.advance(90)  # 150 since the start, 90 since the call
    assert not gone(sessions, session)
    clock.advance(10)  # 100 since the call: polling the state did not extend anything
    assert not gone(sessions, session)
    clock.advance(1)
    assert gone(sessions, session)


@pytest.mark.invariant("I6")
def test_a_refused_call_does_not_keep_a_session_alive() -> None:
    clock = FakeClock()
    sessions = sessions_with(clock)
    session = sessions.start(BEGIN)
    sessions.submit(session.session_id, read(session, "c1"))
    clock.advance(60)
    with pytest.raises(HijackedError, match="duplicate call id"):
        sessions.submit(session.session_id, read(session, "c1"))
    clock.advance(41)  # 101 since the only accepted call
    assert gone(sessions, session)


@pytest.mark.invariant("I6")
def test_a_busy_session_still_expires_at_its_maximum_age() -> None:
    clock = FakeClock()
    sessions = sessions_with(clock, idle_ttl_seconds=100, max_age_seconds=250)
    session = sessions.start(BEGIN)
    for index in range(4):
        clock.advance(60)
        sessions.submit(session.session_id, read(session, f"c{index}"))  # t = 60 .. 240
    assert not gone(sessions, session)
    clock.advance(11)  # t = 251, only 11 seconds since the last call
    assert gone(sessions, session)


@pytest.mark.invariant("I6")
def test_an_expired_session_frees_its_slot_at_the_cap() -> None:
    clock = FakeClock()
    sessions = sessions_with(clock)
    first = sessions.start(BEGIN)
    for _ in range(MAX_SESSIONS - 1):
        sessions.start(BEGIN)
    with pytest.raises(HijackedError) as full:
        sessions.start(BEGIN)
    assert (full.value.status, full.value.detail) == (429, "too many sessions")
    clock.advance(101)
    fresh = sessions.start(BEGIN)  # every old session has expired
    assert not gone(sessions, fresh)
    assert gone(sessions, first)


@pytest.mark.invariant("I6")
def test_expiring_one_session_does_not_touch_another() -> None:
    clock = FakeClock()
    sessions = sessions_with(clock)
    a, b = sessions.start(BEGIN), sessions.start(BEGIN)
    clock.advance(60)
    sessions.submit(b.session_id, read(b, "c1"))
    clock.advance(60)  # a: 120 idle; b: 60 idle
    assert gone(sessions, a)
    assert not gone(sessions, b)
    step = sessions.submit(b.session_id, read(b, "c2"))
    assert {event.run_id for event in step.events} == {b.run_id}


@pytest.mark.invariant("I6")
def test_expiry_over_http_is_a_404_on_every_route() -> None:
    clock = FakeClock()
    sessions = sessions_with(clock)
    client = TestClient(create_app(event_delay=0, hijacked=sessions))
    session = HijackedSession.model_validate_json(
        client.post("/playground/hijacked", json=START).content
    )
    clock.advance(101)
    state = client.get(f"/playground/hijacked/{session.session_id}")
    call = client.post(
        f"/playground/hijacked/{session.session_id}/calls",
        json=read(session, "c1").model_dump(mode="json"),
    )
    for response in (state, call):
        assert (response.status_code, response.json()) == (404, {"detail": "unknown session"})


# ---------------------------------------------------------------------------------- ids


@pytest.mark.invariant("I6")
def test_default_ids_are_unguessable_and_never_repeat() -> None:
    clock = FakeClock()
    sessions = HijackedSessions(clock=clock, idle_ttl_seconds=10, max_sessions_per_client=64)
    seen: set[str] = set()
    for _ in range(1000):
        session = sessions.start(BEGIN)
        assert re.fullmatch(r"[A-Za-z0-9_-]{22,}", session.session_id)
        assert session.run_id == f"run-hijacked-{session.session_id}"
        assert session.session_id not in seen  # not after expiry either
        seen.add(session.session_id)
        clock.advance(11)  # the previous session expires


@pytest.mark.invariant("I6")
def test_ids_are_not_sequential() -> None:
    sessions = HijackedSessions(max_sessions_per_client=64)
    ids = [sessions.start(BEGIN).session_id for _ in range(5)]
    assert not any(re.fullmatch(r"h\d+", session_id) for session_id in ids)
    assert len(set(ids)) == 5


@pytest.mark.invariant("I6")
def test_the_injected_counter_gives_the_ids_of_the_fixtures() -> None:
    sessions = sessions_with(FakeClock())
    first, second = sessions.start(BEGIN), sessions.start(BEGIN)
    assert (first.session_id, second.session_id) == ("h1", "h2")
    assert (first.run_id, second.run_id) == ("run-hijacked-h1", "run-hijacked-h2")


@pytest.mark.invariant("I6")
def test_an_id_that_is_in_use_is_never_handed_out_again() -> None:
    offered = iter(["same", "same", "other"])
    sessions = HijackedSessions(new_id=lambda: next(offered), max_sessions_per_client=64)
    assert sessions.start(BEGIN).session_id == "same"
    assert sessions.start(BEGIN).session_id == "other"


# ------------------------------------------------------------------ the per-client cap


@pytest.mark.invariant("I6")
def test_one_client_holds_a_limited_number_of_sessions() -> None:
    sessions = sessions_with(FakeClock(), max_sessions_per_client=2)
    sessions.start(BEGIN, client="1.1.1.1")
    sessions.start(BEGIN, client="1.1.1.1")
    with pytest.raises(HijackedError) as capped:
        sessions.start(BEGIN, client="1.1.1.1")
    assert (capped.value.status, capped.value.detail) == (
        429,
        "too many sessions for this client",
    )
    sessions.start(BEGIN, client="2.2.2.2")  # another client is not affected


@pytest.mark.invariant("I6")
def test_a_client_gets_a_slot_back_when_its_session_expires() -> None:
    clock = FakeClock()
    sessions = sessions_with(clock, max_sessions_per_client=1)
    sessions.start(BEGIN, client="1.1.1.1")
    with pytest.raises(HijackedError):
        sessions.start(BEGIN, client="1.1.1.1")
    clock.advance(101)
    sessions.start(BEGIN, client="1.1.1.1")


@pytest.mark.invariant("I6")
def test_the_client_of_a_request_is_its_socket_peer() -> None:
    sessions = sessions_with(FakeClock(), max_sessions_per_client=1)
    app = create_app(event_delay=0, hijacked=sessions)
    one = TestClient(app, client=("1.1.1.1", 5000))
    other = TestClient(app, client=("2.2.2.2", 5000))
    assert one.post("/playground/hijacked", json=START).status_code == 200
    capped = one.post("/playground/hijacked", json=START)
    assert (capped.status_code, capped.json()) == (
        429,
        {"detail": "too many sessions for this client"},
    )
    assert other.post("/playground/hijacked", json=START).status_code == 200


# ------------------------------------------------------------------------- rate limits


def limited_app(clock: FakeClock, **settings: float) -> TestClient:
    values = {"hijacked_sessions_per_client": 64, **settings}
    return TestClient(build_app(Settings.model_validate(values), event_delay=0, clock=clock))


@pytest.mark.invariant("I6")
def test_starts_are_rate_limited_per_client() -> None:
    clock = FakeClock()
    client = limited_app(clock, start_limit=3, limit_window_seconds=60)
    for _ in range(3):
        assert client.post("/playground/hijacked", json=START).status_code == 200
    refused = client.post("/playground/hijacked", json=START)
    assert (refused.status_code, refused.json()) == (429, {"detail": "too many requests"})
    assert 1 <= int(refused.headers["Retry-After"]) <= 60
    clock.advance(61)
    assert client.post("/playground/hijacked", json=START).status_code == 200


@pytest.mark.invariant("I6")
def test_a_refused_start_creates_no_session() -> None:
    clock = FakeClock()
    limits = build_limits(Settings(start_limit=1), clock)
    client = TestClient(create_app(event_delay=0, hijacked=sessions_with(clock), limits=limits))
    first = client.post("/playground/hijacked", json=START)
    assert client.post("/playground/hijacked", json=START).status_code == 429
    clock.advance(61)
    second = client.post("/playground/hijacked", json=START)
    # Counter ids: a session made by the refused request would have taken "h2".
    assert (first.json()["session_id"], second.json()["session_id"]) == ("h1", "h2")


@pytest.mark.invariant("I6")
def test_calls_are_rate_limited_and_a_refused_call_spends_no_call_id() -> None:
    clock = FakeClock()
    client = limited_app(clock, call_limit=2, limit_window_seconds=60)
    session = HijackedSession.model_validate_json(
        client.post("/playground/hijacked", json=START).content
    )

    def call(call_id: str):
        return client.post(
            f"/playground/hijacked/{session.session_id}/calls",
            json=read(session, call_id).model_dump(mode="json"),
        )

    assert call("c1").status_code == 200
    assert call("c2").status_code == 200
    refused = call("c3")
    assert (refused.status_code, refused.json()) == (429, {"detail": "too many requests"})
    assert int(refused.headers["Retry-After"]) >= 1
    clock.advance(61)
    assert call("c3").status_code == 200  # the refused attempt did not use up "c3"
    state = client.get(f"/playground/hijacked/{session.session_id}").json()
    assert state["calls"] == 3


@pytest.mark.invariant("I6")
def test_clients_are_limited_independently_over_http() -> None:
    clock = FakeClock()
    app = build_app(
        Settings(start_limit=1, hijacked_sessions_per_client=64), event_delay=0, clock=clock
    )
    one = TestClient(app, client=("1.1.1.1", 1))
    other = TestClient(app, client=("2.2.2.2", 1))
    assert one.post("/playground/hijacked", json=START).status_code == 200
    assert one.post("/playground/hijacked", json=START).status_code == 429
    assert other.post("/playground/hijacked", json=START).status_code == 200


@pytest.mark.invariant("I6")
def test_the_other_playground_posts_share_one_run_budget() -> None:
    clock = FakeClock()
    client = limited_app(clock, run_limit=3, limit_window_seconds=60)
    poison = json.loads(POISON.read_text())
    assert client.post("/playground/attacks/A3/run").status_code == 200
    assert client.post("/playground/poison", json=poison).status_code == 200
    assert client.post("/playground/arena", json=ARENA).status_code == 200
    for refused in (
        client.post("/playground/attacks/A3/run"),
        client.post("/playground/poison", json=poison),
        client.post("/playground/arena", json=ARENA),
    ):
        assert (refused.status_code, refused.json()) == (429, {"detail": "too many requests"})
    # The Hijacked Mode budgets are separate: an exhausted run budget does not block a judge.
    assert client.post("/playground/hijacked", json=START).status_code == 200
    clock.advance(61)
    assert client.post("/playground/attacks/A3/run").status_code == 200


@pytest.mark.invariant("I6")
def test_reads_and_the_run_sockets_are_not_rate_limited() -> None:
    clock = FakeClock()
    client = limited_app(clock, start_limit=1, call_limit=1, run_limit=1)
    for _ in range(20):
        assert client.get("/health").status_code == 200
        assert client.get("/attacks").status_code == 200
        assert client.get("/runs/modes").status_code == 200


@pytest.mark.invariant("I6")
def test_an_app_made_without_limits_does_not_limit() -> None:
    client = TestClient(create_app(event_delay=0, hijacked=sessions_with(FakeClock())))
    for _ in range(30):
        assert client.post("/playground/hijacked", json=START).status_code == 200
