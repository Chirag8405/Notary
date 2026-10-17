"""The read token of the endorsement list (#235): who may READ a card, and nothing else.

Answering and cancelling stay with the owner secret of #233; the token is never accepted there.
"""

import inspect
import json
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketTestSession
from starlette.websockets import WebSocketDisconnect
from test_endorsement import (
    FINAL,
    RunnerSource,
    Waiter,
    add_contact,
    card_frames,
    contacts_added,
    decide_over_socket,
    decision,
    endorsement,
    finish,
    socket_client,
    wait_until,
)
from tokens import HEADERS, OTHER_HEADERS, OTHER_TOKEN, TOKEN, with_token

from notary_core.models import Event
from notary_server.app import create_app
from notary_server.commands import CLOSE_MODE_UNAVAILABLE
from notary_server.endorsement import EndorsementBroker
from notary_server.read_token import (
    MAX_TOKEN_CHARS,
    MIN_TOKEN_CHARS,
    TOKEN_HEADER,
    read_key,
    same_key,
    valid_token,
)
from notary_server.sources import RunMode, RunRequest, RunSource, RunUnavailableError
from notary_world.golden import EVENT_ADAPTER, golden_streams
from notary_world.models import CassetteTurn

URL = "/ws/runs/contacts?mode=cassette"


def script() -> list[CassetteTurn]:
    return [add_contact("Alpha Consulting"), FINAL]


def listed(client: TestClient, run_id: str, headers: dict[str, str] | None = None) -> list[str]:
    response = client.get(f"/runs/{run_id}/endorsements", headers=headers or {})
    assert response.status_code == 200
    return [item["endorsement"]["endorsement_id"] for item in response.json()["pending"]]


# ------------------------------------------------------------------------------ the token


def test_valid_token_accepts_32_to_128_url_safe_characters() -> None:
    assert valid_token("a" * MIN_TOKEN_CHARS)
    assert valid_token("a" * MAX_TOKEN_CHARS)
    assert valid_token("123e4567-e89b-12d3-a456-426614174000")  # a UUID
    assert valid_token("A_b-9" * 8)


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "a" * (MIN_TOKEN_CHARS - 1),
        "a" * (MAX_TOKEN_CHARS + 1),
        "a" * 31 + ".",
        "a" * 31 + " ",
        "a" * 32 + "\n",
        "a" * 31 + "é",
        "a" * 31 + "/",
    ],
)
def test_valid_token_rejects_everything_else(token: str | None) -> None:
    assert not valid_token(token)


def test_read_key_depends_on_the_key_the_run_and_the_token() -> None:
    base = read_key(b"k" * 32, "run-a", TOKEN)
    assert len(base) == 32
    assert base == read_key(b"k" * 32, "run-a", TOKEN)
    assert base != read_key(b"j" * 32, "run-a", TOKEN)
    assert base != read_key(b"k" * 32, "run-b", TOKEN)
    assert base != read_key(b"k" * 32, "run-a", OTHER_TOKEN)
    assert TOKEN.encode() not in base


def test_read_key_separates_the_run_id_from_the_token() -> None:
    key = b"k" * 32
    assert read_key(key, "a", "bc") != read_key(key, "ab", "c")


def test_same_key_is_false_for_a_missing_key() -> None:
    key = read_key(b"k" * 32, "r", TOKEN)
    assert same_key(key, key)
    assert not same_key(key, read_key(b"k" * 32, "r", OTHER_TOKEN))
    assert not same_key(None, key)
    assert not same_key(key, None)
    assert not same_key(None, None)


# --------------------------------------------------------------------------- the list route


@pytest.mark.invariant("I4")
def test_a_tab_sees_only_its_own_cards() -> None:
    source = RunnerSource(EndorsementBroker(), script())
    client = socket_client(source)
    with (
        client.websocket_connect(with_token(URL, TOKEN)) as mine,
        client.websocket_connect(with_token(URL, OTHER_TOKEN)) as theirs,
    ):
        my_card = card_frames(mine)
        assert card_frames(theirs).run_id == my_card.run_id
        run_id = my_card.run_id
        wait_until(lambda: len(source.broker.pending_for_run(run_id)) == 2)
        # Two cards share the run id; each token lists exactly the card of its own socket.
        assert listed(client, run_id, HEADERS) == [my_card.endorsement.endorsement_id]
        assert listed(client, run_id, OTHER_HEADERS) == [my_card.endorsement.endorsement_id]
        assert len(source.broker.pending_for_run(run_id)) == 2
        decide_over_socket(mine, run_id, my_card.endorsement.endorsement_id, "reject")
        finish(mine)
        assert listed(client, run_id, HEADERS) == []
        assert len(listed(client, run_id, OTHER_HEADERS)) == 1
        decide_over_socket(theirs, run_id, my_card.endorsement.endorsement_id, "reject")
        finish(theirs)


@pytest.mark.invariant("I4")
@pytest.mark.parametrize(
    "headers",
    [
        {},
        {TOKEN_HEADER: ""},
        {TOKEN_HEADER: "a" * (MIN_TOKEN_CHARS - 1)},
        {TOKEN_HEADER: "a" * (MAX_TOKEN_CHARS + 1)},
        {TOKEN_HEADER: "a" * 31 + "."},
        {TOKEN_HEADER: "b" * 36},  # well-formed, held by nobody
        {TOKEN_HEADER.lower(): "c" * 36},
    ],
    ids=["none", "empty", "short", "long", "bad-chars", "wrong", "wrong-lowercase"],
)
def test_no_token_and_a_wrong_token_see_nothing(headers: dict[str, str]) -> None:
    source = RunnerSource(EndorsementBroker(), script())
    client = socket_client(source)
    with client.websocket_connect(with_token(URL)) as ws:
        card = card_frames(ws)
        wait_until(lambda: len(source.broker.pending_for_run(card.run_id)) == 1)
        response = client.get(f"/runs/{card.run_id}/endorsements", headers=headers)
        assert (response.status_code, response.json()) == (200, {"pending": []})
        assert len(listed(client, card.run_id, HEADERS)) == 1  # the holder still sees it
        decide_over_socket(ws, card.run_id, card.endorsement.endorsement_id, "reject")
        finish(ws)


@pytest.mark.invariant("I4")
def test_a_token_lists_nothing_for_another_run_id() -> None:
    """The key binds the token to the run id: the same token on another run id finds nothing."""
    source = RunnerSource(EndorsementBroker(), script())
    client = socket_client(source)
    with client.websocket_connect(with_token(URL)) as ws:
        card = card_frames(ws)
        wait_until(lambda: len(source.broker.pending_for_run(card.run_id)) == 1)
        assert listed(client, "run-contacts-undefended", HEADERS) == []
        assert listed(client, "nope", HEADERS) == []
        decide_over_socket(ws, card.run_id, card.endorsement.endorsement_id, "reject")
        finish(ws)


@pytest.mark.invariant("I4")
def test_two_same_id_tabs_resolve_independently() -> None:
    """The stuck-UI case: tab A answers its card; A's list empties while B's card is still listed
    and still answerable. Before the token, A kept seeing B's card and never saw its own resolve."""
    source = RunnerSource(EndorsementBroker(), script())
    client = socket_client(source)
    with (
        client.websocket_connect(with_token(URL, TOKEN)) as tab_a,
        client.websocket_connect(with_token(URL, OTHER_TOKEN)) as tab_b,
    ):
        card = card_frames(tab_a)
        assert card_frames(tab_b).endorsement == card.endorsement
        run_id, card_id = card.run_id, card.endorsement.endorsement_id
        wait_until(lambda: len(source.broker.pending_for_run(run_id)) == 2)
        decide_over_socket(tab_a, run_id, card_id, "approve")
        assert finish(tab_a).code == 1000
        assert listed(client, run_id, HEADERS) == []  # A's card resolved: A's list is empty
        assert listed(client, run_id, OTHER_HEADERS) == [card_id]  # B's card is untouched
        decide_over_socket(tab_b, run_id, card_id, "reject")
        assert finish(tab_b).code == 1000
        assert listed(client, run_id, OTHER_HEADERS) == []
    assert [contacts_added(record) for record in source.records] == [True, False]


# ------------------------------------------- the token is never an answer or cancel credential


@pytest.mark.invariant("I4")
def test_a_copied_token_answers_and_cancels_nothing_of_the_owner() -> None:
    """Tab B uses the very token of tab A. It can read the same list, but its decision lands on
    its own card, and its socket closing rejects only its own card."""
    source = RunnerSource(EndorsementBroker(), script())
    client = socket_client(source)
    with client.websocket_connect(with_token(URL, TOKEN)) as owner:
        card = card_frames(owner)
        run_id, card_id = card.run_id, card.endorsement.endorsement_id
        wait_until(lambda: len(source.broker.pending_for_run(run_id)) == 1)
        with client.websocket_connect(with_token(URL, TOKEN)) as copy:
            card_frames(copy)
            wait_until(lambda: len(source.broker.pending_for_run(run_id)) == 2)
            decide_over_socket(copy, run_id, card_id, "approve")
            assert finish(copy).code == 1000
        # The copy answered and left; the owner's card is untouched and answerable.
        wait_until(lambda: len(source.broker.pending_for_run(run_id)) == 1)
        assert contacts_added(source.records[0])  # the copy's own run, not the owner's
        assert len(listed(client, run_id, HEADERS)) == 1
        with client.websocket_connect(with_token(URL, TOKEN)) as leaver:
            card_frames(leaver)
            wait_until(lambda: len(source.broker.pending_for_run(run_id)) == 2)
        wait_until(lambda: len(source.broker.pending_for_run(run_id)) == 1)  # leaver cancelled
        assert len(listed(client, run_id, HEADERS)) == 1  # ... and only itself
        decide_over_socket(owner, run_id, card_id, "reject")
        assert finish(owner).code == 1000


@pytest.mark.invariant("I4")
def test_a_decision_with_a_token_field_is_refused() -> None:
    """`token` is not a field of any command: the strict model refuses it (4400), the card stays."""
    source = RunnerSource(EndorsementBroker(), script())
    client = socket_client(source)
    with client.websocket_connect(with_token(URL)) as ws:
        card = card_frames(ws)
        wait_until(lambda: len(source.broker.pending_for_run(card.run_id)) == 1)
        command = {
            "type": "endorsement_decision",
            "run_id": card.run_id,
            "endorsement_id": card.endorsement.endorsement_id,
            "decision": "approve",
            "token": TOKEN,
        }
        ws.send_text(json.dumps(command))
        closed = finish(ws)
    assert (closed.code, closed.reason) == (4400, "invalid command")
    assert not any(contacts_added(record) for record in source.records)


@pytest.mark.invariant("I4")
def test_the_token_is_not_a_parameter_of_submit_or_cancel() -> None:
    for method in (
        EndorsementBroker.submit,
        EndorsementBroker.cancel_run,
        EndorsementBroker.pending,
    ):
        names = set(inspect.signature(method).parameters)
        assert not {"token", "read_key"} & names, method.__name__


@pytest.mark.invariant("I4")
def test_a_digest_or_token_is_not_an_owner() -> None:
    """The stored digest and the raw token, in any spelling, answer and cancel nothing: only the
    owner string the broker was started with does."""
    broker = EndorsementBroker()
    digest = read_key(b"k" * 32, "r1", TOKEN)
    run = broker.start_run("r1", owner="the-owner", max_approvals=1, read_key=digest)
    waiter = Waiter(run.decide, endorsement())
    wait_until(lambda: len(broker.pending("r1", owner="the-owner")) == 1)
    for impostor in (digest.hex(), digest.decode("latin-1"), TOKEN, TOKEN.upper(), ""):
        assert broker.submit(decision(), owner=impostor) == "unknown_endorsement"
        broker.cancel_run("r1", owner=impostor)
        assert broker.pending("r1", owner=impostor) == ()
    assert waiter.result is None
    assert len(broker.pending("r1", owner="the-owner")) == 1
    assert broker.submit(decision(), owner="the-owner") == "accepted"
    assert waiter.join() == "approve"


@pytest.mark.invariant("I4")
def test_the_token_header_on_a_socket_handshake_is_ignored() -> None:
    """Only `?token=` counts on a socket. A handshake header with another token neither changes
    whose cards the socket's list shows nor is read anywhere."""
    source = RunnerSource(EndorsementBroker(), script())
    client = socket_client(source)
    with client.websocket_connect(
        with_token(URL, TOKEN), headers={TOKEN_HEADER: OTHER_TOKEN}
    ) as ws:
        card = card_frames(ws)
        wait_until(lambda: len(source.broker.pending_for_run(card.run_id)) == 1)
        assert len(listed(client, card.run_id, HEADERS)) == 1
        assert listed(client, card.run_id, OTHER_HEADERS) == []
        decide_over_socket(ws, card.run_id, card.endorsement.endorsement_id, "reject")
        finish(ws)


# ------------------------------------------------------------------- the socket and its token


class CountingSource:
    """A source that counts how often it was started and can say it is unavailable."""

    def __init__(self, unavailable: bool = False) -> None:
        self.started = 0
        self._unavailable = unavailable
        self.requests: list[RunRequest] = []

    def check_available(self) -> None:
        if self._unavailable:
            raise RunUnavailableError(CLOSE_MODE_UNAVAILABLE, "mode not available")

    def events(self, request: RunRequest) -> Iterator[Event]:
        self.check_available()
        self.started += 1
        self.requests.append(request)
        return iter(golden_streams()["poisoned_bill.notary"][:2])


BAD_QUERIES = {
    "missing": "",
    "empty": "&token=",
    "short": "&token=" + "a" * (MIN_TOKEN_CHARS - 1),
    "long": "&token=" + "a" * (MAX_TOKEN_CHARS + 1),
    "bad-chars": "&token=" + "a" * 31 + ".",
    "twice": f"&token={TOKEN}&token={OTHER_TOKEN}",
    "wrong-name": f"&Token={TOKEN}",
}


@pytest.mark.invariant("I4")
@pytest.mark.parametrize("mode", ["cassette", "live"])
@pytest.mark.parametrize("shape", sorted(BAD_QUERIES))
def test_a_broker_mode_socket_without_a_good_token_closes_4400(mode: RunMode, shape: str) -> None:
    broker = EndorsementBroker()
    counting = CountingSource()
    sources: dict[RunMode, RunSource] = {mode: counting}
    client = TestClient(create_app(event_delay=0, sources=sources, broker=broker))
    path = f"/ws/runs/poisoned_bill?mode={mode}{BAD_QUERIES[shape]}"
    with client.websocket_connect(path) as ws:
        frames, closed = drain(ws)
    assert frames == []
    assert (closed.code, closed.reason) == (4400, "invalid token")
    assert counting.started == 0  # the source never started
    assert broker.pending_for_run("run-poisoned_bill-notary") == ()


def drain(ws: WebSocketTestSession) -> tuple[list[str], WebSocketDisconnect]:
    frames: list[str] = []
    while True:
        try:
            frames.append(ws.receive_text())
        except WebSocketDisconnect as closed:
            return frames, closed


@pytest.mark.invariant("I4")
@pytest.mark.parametrize("mode", ["cassette", "live"])
def test_a_good_token_opens_the_socket_and_only_its_digest_reaches_the_source(
    mode: RunMode,
) -> None:
    counting = CountingSource()
    sources: dict[RunMode, RunSource] = {mode: counting}
    key = b"s" * 32
    client = TestClient(create_app(event_delay=0, sources=sources, server_key=key))
    with client.websocket_connect(f"/ws/runs/poisoned_bill?mode={mode}&token={TOKEN}") as ws:
        frames, closed = drain(ws)
    assert (len(frames), closed.code) == (2, 1000)
    (request,) = counting.requests
    assert request.read_key == read_key(key, "run-poisoned_bill-notary", TOKEN)
    assert TOKEN not in repr(request)


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("query", ["", "&token=x", "&token=" + "a" * 31 + "."])
def test_a_golden_socket_needs_no_token(query: str) -> None:
    """Golden owns no card: no token, or a malformed one, streams to the end as before."""
    broker = EndorsementBroker()
    client = TestClient(create_app(event_delay=0, broker=broker))
    golden = golden_streams()["poisoned_bill.notary"]
    with client.websocket_connect(f"/ws/runs/poisoned_bill?lane=notary&mode=golden{query}") as ws:
        frames, closed = drain(ws)
    assert closed.code == 1000
    assert [EVENT_ADAPTER.validate_json(f) for f in frames] == list(golden)
    assert broker.pending_for_run("run-poisoned_bill-notary") == ()


@pytest.mark.invariant("I6")
def test_mode_not_available_wins_over_an_invalid_token() -> None:
    """`live` without a key answers 4501 even though it has no token either."""
    unavailable = CountingSource(unavailable=True)
    client = TestClient(create_app(event_delay=0, sources={"live": unavailable}))
    with client.websocket_connect("/ws/runs/poisoned_bill?mode=live") as ws:
        frames, closed = drain(ws)
    assert (frames, closed.code, closed.reason) == ([], 4501, "mode not available")
    with client.websocket_connect("/ws/runs/poisoned_bill?mode=cassette") as ws:  # no source
        frames, closed = drain(ws)
    assert (frames, closed.code, closed.reason) == ([], 4501, "mode not available")
    assert unavailable.started == 0
