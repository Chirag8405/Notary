"""Mode `mcp`: the server tails the proxy's audit chains, verifies them and streams the events.

The chain files are written by the proxy's own `RunLog`. The tests drive the tailer by steps (a
no-op poll, `None` when nothing is new), so none of them waits on a clock.
"""

import json
import os
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketTestSession
from starlette.websockets import WebSocketDisconnect

from notary_core.audit import append
from notary_core.models import AuditEntry, Event, RunFinished
from notary_mcp_proxy.audit_log import ANCHOR_SUFFIX, CHAIN_SUFFIX, RunLog
from notary_server.anchors import AnchorStore
from notary_server.app import create_app
from notary_server.mcp_runs import (
    CLOSE_CHAIN_BROKEN,
    MAX_LINE_BYTES,
    McpRunsSource,
    list_mcp_runs,
)
from notary_server.sources import RunRequest, RunUnavailableError
from notary_server.wiring import Settings, build_app
from notary_world.golden import EVENT_ADAPTER, golden_streams

RUN = "mcp-0123456789ab"
OTHER = "mcp-ba9876543210"


def run_events(run_id: str, count: int | None = None, *, finish: bool = True) -> list[Event]:
    """The golden NOTARY stream of the poisoned bill, retargeted to a proxy run id.

    `count` keeps the first events; `finish` ends the run with the stream's `run_finished`.
    """
    stream = golden_streams()["poisoned_bill.notary"]
    body = [event.model_copy(update={"run_id": run_id}) for event in stream[:-1]]
    last = stream[-1]
    assert isinstance(last, RunFinished)
    events = body[:count] if count is not None else body
    if finish:
        events = [*events, last.model_copy(update={"run_id": run_id, "seq": len(events)})]
    return events


def entries_of(events: Sequence[Event]) -> tuple[AuditEntry, ...]:
    chain: tuple[AuditEntry, ...] = ()
    for event in events:
        chain = append(chain, event)
    return chain


def write_run(directory: Path, run_id: str, entries: Sequence[AuditEntry]) -> Path:
    log = RunLog(directory, run_id)
    for entry in entries:
        log.write(entry)
    log.close()
    return log.chain_path


def step(events: Iterator[Event | None]) -> Event | None:
    return next(events)


def drain(events: Iterator[Event | None]) -> list[Event]:
    """Everything up to the first idle step."""
    seen: list[Event] = []
    while (event := step(events)) is not None:
        seen.append(event)
    return seen


def source_for(directory: Path, anchors: AnchorStore | None = None) -> McpRunsSource:
    return McpRunsSource(directory, poll=lambda: None, anchors=anchors)


def request(run_id: str) -> RunRequest:
    return RunRequest(scenario=run_id, lane="notary", mode="mcp")


def rewrite_lines(path: Path, edit: dict[int, str]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, replacement in edit.items():
        lines[index] = replacement
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def until_broken(events: Iterator[Event | None]) -> tuple[list[Event], RunUnavailableError]:
    """Step until the stream is refused: the events before that and the refusal."""
    seen: list[Event] = []
    try:
        while True:
            event = step(events)
            if event is not None:
                seen.append(event)
    except RunUnavailableError as broken:
        return seen, broken


def assert_broken(events: Iterator[Event | None]) -> None:
    _, broken = until_broken(events)
    assert (broken.code, broken.reason) == (CLOSE_CHAIN_BROKEN, "chain broken")


def drain_until_broken(events: Iterator[Event | None]) -> list[Event]:
    seen, broken = until_broken(events)
    assert (broken.code, broken.reason) == (CLOSE_CHAIN_BROKEN, "chain broken")
    return seen


def test_replays_then_follows_and_ends_after_run_finished(tmp_path: Path) -> None:
    events = run_events(RUN, 5)
    assert len(events) == 6
    entries = entries_of(events)
    log = RunLog(tmp_path, RUN)
    for entry in entries[:3]:
        log.write(entry)
    polls: list[None] = []
    stream = McpRunsSource(tmp_path, poll=lambda: polls.append(None)).events(request(RUN))
    got = drain(stream)
    assert got == events[:3]
    assert len(polls) == 1  # one wait, then the idle step
    for entry in entries[3:5]:
        log.write(entry)
    got.extend(drain(stream))
    assert got == events[:5]
    log.write(entries[5])
    log.close()
    last = step(stream)
    assert last == events[5]
    assert last is not None
    assert last.type == "run_finished"
    with pytest.raises(StopIteration):
        step(stream)


def test_a_half_written_line_is_waited_for(tmp_path: Path) -> None:
    events = run_events(RUN, 2, finish=False)
    first, second = entries_of(events)
    path = write_run(tmp_path, RUN, [first])
    line = (second.model_dump_json() + "\n").encode("utf-8")
    stream = source_for(tmp_path).events(request(RUN))
    assert drain(stream) == events[:1]
    with path.open("ab") as out:
        out.write(line[:40])
        out.flush()
        assert step(stream) is None  # a partial line is neither parsed nor corruption
        assert step(stream) is None
        out.write(line[40:-1])
        out.flush()
        assert step(stream) is None  # complete JSON, but its newline is not written yet
        out.write(line[-1:])
    assert drain(stream) == events[1:]


def test_an_empty_chain_is_open_until_the_first_line(tmp_path: Path) -> None:
    log = RunLog(tmp_path, RUN)
    stream = source_for(tmp_path).events(request(RUN))
    assert step(stream) is None
    first = entries_of(run_events(RUN, 1, finish=False))[0]
    log.write(first)
    log.close()
    assert drain(stream) == run_events(RUN, 1, finish=False)


def test_an_edited_middle_line_stops_the_stream_before_it(tmp_path: Path) -> None:
    entries = entries_of(run_events(RUN))
    path = write_run(tmp_path, RUN, entries)
    forged = json.loads(entries[3].model_dump_json())
    forged["event"]["seq"] = 99
    rewrite_lines(path, {3: json.dumps(forged)})
    stream = source_for(tmp_path).events(request(RUN))
    assert [step(stream) for _ in range(3)] == [entry.event for entry in entries[:3]]
    assert_broken(stream)


def test_a_chain_that_is_edited_while_followed_stops_at_the_edit(tmp_path: Path) -> None:
    entries = entries_of(run_events(RUN))
    log = RunLog(tmp_path, RUN)
    for entry in entries[:2]:
        log.write(entry)
    stream = source_for(tmp_path).events(request(RUN))
    assert len(drain(stream)) == 2
    forged = json.loads(entries[2].model_dump_json())
    forged["prev_hash"] = "1" * 64
    with log.chain_path.open("ab") as out:
        out.write((json.dumps(forged) + "\n").encode("utf-8"))
    assert_broken(stream)


@pytest.mark.parametrize(
    "bad",
    [
        "not json",
        "{}",
        "",
        '{"index": 2}',
    ],
)
def test_a_complete_line_that_is_not_an_entry_is_corruption(tmp_path: Path, bad: str) -> None:
    entries = entries_of(run_events(RUN))
    path = write_run(tmp_path, RUN, entries)
    rewrite_lines(path, {2: bad})
    stream = source_for(tmp_path).events(request(RUN))
    assert [step(stream) for _ in range(2)] == [entry.event for entry in entries[:2]]
    assert_broken(stream)


def test_a_dropped_line_and_a_reordered_line_are_corruption(tmp_path: Path) -> None:
    entries = entries_of(run_events(RUN))
    path = write_run(tmp_path, RUN, entries)
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[2]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    stream = source_for(tmp_path).events(request(RUN))
    assert len(drain_until_broken(stream)) == 2


def test_events_of_another_run_in_a_valid_chain_are_refused(tmp_path: Path) -> None:
    """The hash chain does not bind a file name; the event's own run id must match it."""
    path = write_run(tmp_path, RUN, entries_of(run_events(OTHER)))
    assert path.name == RUN + CHAIN_SUFFIX
    stream = source_for(tmp_path).events(request(RUN))
    assert drain_until_broken(stream) == []


def test_a_file_that_shrinks_is_corruption(tmp_path: Path) -> None:
    entries = entries_of(run_events(RUN))
    log = RunLog(tmp_path, RUN)
    for entry in entries[:4]:
        log.write(entry)
    stream = source_for(tmp_path).events(request(RUN))
    assert len(drain(stream)) == 4
    lines = log.chain_path.read_text(encoding="utf-8").splitlines()
    log.chain_path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    assert_broken(stream)


def test_a_line_that_never_ends_is_refused(tmp_path: Path) -> None:
    path = write_run(tmp_path, RUN, entries_of(run_events(RUN, 1, finish=False)))
    stream = source_for(tmp_path).events(request(RUN))
    assert len(drain(stream)) == 1
    with path.open("ab") as out:
        out.write(b"x" * (MAX_LINE_BYTES + 1))
    assert_broken(stream)


def test_the_stored_anchor_is_a_second_copy_of_the_head(tmp_path: Path) -> None:
    entries = entries_of(run_events(RUN))
    write_run(tmp_path, RUN, entries)
    anchors = AnchorStore()
    stream = source_for(tmp_path, anchors).events(request(RUN))
    assert len(drain_until_end(stream)) == len(entries)
    stored = anchors.get(RUN)
    assert stored is not None
    assert (stored.length, stored.head) == (len(entries), entries[-1].hash)
    again = source_for(tmp_path, anchors).events(request(RUN))  # a second watcher agrees
    assert len(drain_until_end(again)) == len(entries)
    assert anchors.get(RUN) == stored


def drain_until_end(events: Iterator[Event | None]) -> list[Event]:
    return [event for event in events if event is not None]


def test_a_rewritten_chain_disagrees_with_the_stored_anchor(tmp_path: Path) -> None:
    entries = entries_of(run_events(RUN))
    anchors = AnchorStore()
    anchors.record(RUN, "a" * 64, 2)  # what an earlier watcher saw at length 2
    write_run(tmp_path, RUN, entries)
    stream = source_for(tmp_path, anchors).events(request(RUN))
    assert drain_until_broken(stream) == [entry.event for entry in entries[:1]]


@pytest.mark.parametrize(
    "run_id",
    [
        "../x",
        "..",
        "mcp-xyz",
        "mcp-0123456789AB",
        "mcp-0123456789abc",
        "mcp-0123456789a",
        f"{RUN}/../{OTHER}",
        f"{RUN}.chain.jsonl",
        "/etc/passwd",
        "",
    ],
)
def test_a_run_id_that_is_not_a_proxy_run_id_is_never_opened(tmp_path: Path, run_id: str) -> None:
    write_run(tmp_path, RUN, entries_of(run_events(RUN)))
    (tmp_path / "x.chain.jsonl").write_text("{}\n", encoding="utf-8")
    with pytest.raises(KeyError):
        source_for(tmp_path).events(request(run_id))


def test_a_run_without_a_chain_file_is_unknown(tmp_path: Path) -> None:
    with pytest.raises(KeyError):
        source_for(tmp_path).events(request(RUN))
    with pytest.raises(KeyError):
        source_for(tmp_path / "missing").events(request(RUN))


def test_a_symlinked_chain_is_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    runs = tmp_path / "runs"
    runs.mkdir()
    real = write_run(outside, RUN, entries_of(run_events(RUN)))
    (runs / (RUN + CHAIN_SUFFIX)).symlink_to(real)
    with pytest.raises(KeyError):
        source_for(runs).events(request(RUN))


def test_listing_is_newest_first_with_the_lengths_of_the_anchors(tmp_path: Path) -> None:
    ids = ["mcp-000000000001", "mcp-000000000002", "mcp-000000000003"]
    write_run(tmp_path, ids[0], entries_of(run_events(ids[0])))  # finished
    write_run(tmp_path, ids[1], entries_of(run_events(ids[1], 3, finish=False)))  # open
    write_run(tmp_path, ids[2], ())  # empty so far
    for age, run_id in enumerate(ids):
        stamp = 1_700_000_000 + age * 100
        os.utime(tmp_path / (run_id + ANCHOR_SUFFIX), (stamp, stamp))
    listed = list_mcp_runs(tmp_path)
    assert [info.run_id for info in listed] == [ids[2], ids[1], ids[0]]
    assert [(info.length, info.finished) for info in listed] == [(0, False), (3, False), (11, True)]
    assert listed[0].head is None
    assert listed[1].head == entries_of(run_events(ids[1], 3, finish=False))[-1].hash


def test_listing_skips_what_is_not_a_run(tmp_path: Path) -> None:
    write_run(tmp_path, RUN, entries_of(run_events(RUN, 2, finish=False)))
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
    (tmp_path / "mcp-abc.anchor.json").write_text("{}", encoding="utf-8")
    (tmp_path / (OTHER + ANCHOR_SUFFIX)).write_text("{not json", encoding="utf-8")  # no chain
    (tmp_path / (OTHER + CHAIN_SUFFIX)).write_text("", encoding="utf-8")
    (tmp_path / (RUN + ANCHOR_SUFFIX + ".tmp")).write_text("{}", encoding="utf-8")
    other_anchor = {"run_id": RUN, "length": 1, "head": None}  # names another run
    (tmp_path / "mcp-111111111111.anchor.json").write_text(json.dumps(other_anchor), "utf-8")
    (tmp_path / "mcp-111111111111.chain.jsonl").write_text("", encoding="utf-8")
    assert [info.run_id for info in list_mcp_runs(tmp_path)] == [RUN]
    assert list_mcp_runs(tmp_path / "missing") == ()


def mcp_client(directory: Path | None) -> TestClient:
    settings = Settings() if directory is None else Settings(mcp_runs_dir=directory)
    return TestClient(build_app(settings, event_delay=0))


def test_without_a_directory_mode_mcp_does_not_exist(tmp_path: Path) -> None:
    client = mcp_client(None)
    assert "mcp" not in client.get("/runs/modes").json()["modes"]
    assert client.get("/mcp/runs").status_code == 404
    streamed, closed = socket_events(client, RUN)
    assert streamed == []
    assert (closed.code, closed.reason) == (4501, "mode not available")


def test_with_a_directory_the_mode_and_the_route_exist(tmp_path: Path) -> None:
    write_run(tmp_path, RUN, entries_of(run_events(RUN)))
    client = mcp_client(tmp_path)
    assert client.get("/runs/modes").json() == {"modes": ["cassette", "golden", "live", "mcp"]}
    body = client.get("/mcp/runs").json()
    assert body == {
        "runs": [
            {
                "run_id": RUN,
                "length": 11,
                "head": entries_of(run_events(RUN))[-1].hash,
                "finished": True,
            }
        ]
    }


def socket_events(client: TestClient, run_id: str) -> tuple[list[Event], WebSocketDisconnect]:
    events: list[Event] = []
    with client.websocket_connect(f"/ws/runs/{run_id}?lane=notary&mode=mcp") as ws:
        while True:
            try:
                events.append(EVENT_ADAPTER.validate_json(ws.receive_text()))
            except WebSocketDisconnect as closed:
                return events, closed


def test_a_finished_run_streams_over_the_socket_and_closes_normally(tmp_path: Path) -> None:
    events = run_events(RUN)
    write_run(tmp_path, RUN, entries_of(events))
    streamed, closed = socket_events(mcp_client(tmp_path), RUN)
    assert streamed == events
    assert closed.code == 1000


def test_a_broken_chain_closes_the_socket_after_the_last_valid_event(tmp_path: Path) -> None:
    entries = entries_of(run_events(RUN))
    path = write_run(tmp_path, RUN, entries)
    rewrite_lines(path, {4: "garbage"})
    streamed, closed = socket_events(mcp_client(tmp_path), RUN)
    assert streamed == [entry.event for entry in entries[:4]]
    assert (closed.code, closed.reason) == (CLOSE_CHAIN_BROKEN, "chain broken")


@pytest.mark.parametrize("run_id", ["mcp-xyz", "mcp-0123456789AB", RUN])
def test_an_unknown_or_invalid_run_closes_4404(tmp_path: Path, run_id: str) -> None:
    streamed, closed = socket_events(mcp_client(tmp_path), run_id)
    assert streamed == []
    assert (closed.code, closed.reason) == (4404, "unknown scenario")


def until_closed(ws: WebSocketTestSession) -> WebSocketDisconnect:
    while True:
        try:
            ws.receive_text()
        except WebSocketDisconnect as closed:
            return closed


def test_a_command_on_an_mcp_socket_is_rejected(tmp_path: Path) -> None:
    events = run_events(RUN, 3, finish=False)
    write_run(tmp_path, RUN, entries_of(events))
    app = create_app(
        event_delay=0,
        sources={"mcp": source_for(tmp_path)},
        mcp_runs_dir=tmp_path,
    )
    command = json.dumps(
        {
            "type": "endorsement_decision",
            "run_id": RUN,
            "endorsement_id": "e1",
            "decision": "approve",
        }
    )
    with TestClient(app).websocket_connect(f"/ws/runs/{RUN}?lane=notary&mode=mcp") as ws:
        for _ in events:
            ws.receive_text()
        ws.send_text(command)
        closed = until_closed(ws)
    assert (closed.code, closed.reason) == (4422, "command not supported on this socket")


def test_a_socket_that_leaves_an_idle_run_ends_the_stream(tmp_path: Path) -> None:
    write_run(tmp_path, RUN, entries_of(run_events(RUN, 2, finish=False)))
    app = create_app(event_delay=0, sources={"mcp": source_for(tmp_path)}, mcp_runs_dir=tmp_path)
    with TestClient(app).websocket_connect(f"/ws/runs/{RUN}?lane=notary&mode=mcp") as ws:
        first = EVENT_ADAPTER.validate_json(ws.receive_text())
        second = EVENT_ADAPTER.validate_json(ws.receive_text())
        assert (first.type, second.type) == ("run_started", "call_proposed")
    # leaving the context closes the socket; the tailer's idle step ends the server task


def test_settings_read_the_runs_directory_from_the_environment(tmp_path: Path) -> None:
    assert Settings.from_env({}).mcp_runs_dir is None
    assert Settings.from_env({"NOTARY_MCP_RUNS_DIR": ""}).mcp_runs_dir is None
    settings = Settings.from_env({"NOTARY_MCP_RUNS_DIR": str(tmp_path)})
    assert settings.mcp_runs_dir == tmp_path
