"""Audit anchors: a copy of the chain head and length kept outside the log."""

import threading
from collections.abc import Sequence
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from notary_core.audit import GENESIS_HASH, append, verify_chain, verify_chain_detailed
from notary_core.models import AuditEntry, Event
from notary_server.anchors import Anchor, AnchorStore, anchored_append, verify_against_anchor
from notary_server.app import create_app
from notary_world.executor import AuditAppend, RunRecord, execute_run
from notary_world.golden import golden_streams
from notary_world.scenarios import get_scenario, golden_run_id

HEAD_A = "a" * 64
HEAD_B = "b" * 64
RUN_ID = golden_run_id("legitimate_bill", "notary")
EVENTS = golden_streams()["poisoned_bill.notary"]


def run_with(store: AnchorStore) -> RunRecord:
    scenario = get_scenario("legitimate_bill", 0)
    return execute_run(
        scenario=scenario.scenario_id,
        run_id=RUN_ID,
        request=scenario.user_request,
        world=scenario.world,
        contract=scenario.contract,
        ledger=scenario.ledger,
        session=scenario.session,
        calls=scenario.calls,
        audit_append=anchored_append(store),
    )


def feed(wrapper: AuditAppend, events: Sequence[Event]) -> tuple[AuditEntry, ...]:
    chain: tuple[AuditEntry, ...] = ()
    for event in events:
        chain = wrapper(chain, event)
    return chain


@pytest.mark.invariant("I1")
def test_record_get_and_upsert() -> None:
    store = AnchorStore()
    assert store.get("r1") is None
    store.record("r1", HEAD_A, 3)
    store.record("r1", HEAD_B, 4)
    assert store.get("r1") == Anchor(run_id="r1", head=HEAD_B, length=4)
    assert store.get("r2") is None


@pytest.mark.invariant("I1")
@pytest.mark.parametrize(
    ("head", "length"),
    [("z" * 64, 1), ("a" * 63, 1), ("A" * 64, 1), (HEAD_A, -1)],
    ids=["not-hex", "too-short", "uppercase", "negative-length"],
)
def test_invalid_anchor_values(head: str, length: int) -> None:
    store = AnchorStore()
    with pytest.raises(ValueError, match="invalid anchor"):
        store.record("r1", head, length)
    assert store.get("r1") is None


@pytest.mark.invariant("I1")
def test_anchor_never_moves_backwards() -> None:
    store = AnchorStore()
    store.record("r1", HEAD_A, 5)
    with pytest.raises(ValueError, match="anchor cannot move backwards"):
        store.record("r1", HEAD_B, 4)
    assert store.get("r1") == Anchor(run_id="r1", head=HEAD_A, length=5)
    store.record("r1", HEAD_B, 5)
    assert store.get("r1") == Anchor(run_id="r1", head=HEAD_B, length=5)


@pytest.mark.invariant("I1")
def test_hostile_run_id_is_data() -> None:
    store = AnchorStore()
    hostile = "x'); DROP TABLE anchors;--"
    store.record(hostile, HEAD_A, 1)
    assert store.get(hostile) == Anchor(run_id=hostile, head=HEAD_A, length=1)
    store.record("r1", HEAD_B, 2)
    assert store.get("r1") is not None


@pytest.mark.invariant("I1")
def test_persists_across_reopen(tmp_path: Path) -> None:
    path = str(tmp_path / "anchors.sqlite")
    first = AnchorStore(path)
    first.record("r1", HEAD_A, 7)
    first.close()
    second = AnchorStore(path)
    assert second.get("r1") == Anchor(run_id="r1", head=HEAD_A, length=7)
    second.close()


@pytest.mark.invariant("I1")
def test_closed_store_cannot_be_used() -> None:
    store = AnchorStore()
    store.close()
    with pytest.raises(Exception, match="closed database"):
        store.get("r1")


@pytest.mark.invariant("I1")
def test_anchored_append_tracks_every_append() -> None:
    store = AnchorStore()
    wrapper = anchored_append(store)
    chain: tuple[AuditEntry, ...] = ()
    for event in EVENTS[:5]:
        chain = wrapper(chain, event)
        assert store.get(event.run_id) == Anchor(
            run_id=event.run_id, head=chain[-1].hash, length=len(chain)
        )


class FailingStore(AnchorStore):
    def record(self, run_id: str, head: str, length: int) -> None:
        raise OSError("disk full")

    def restart(self, run_id: str, head: str) -> None:
        raise OSError("disk full")


@pytest.mark.invariant("I1")
def test_anchored_append_propagates_failures() -> None:
    with pytest.raises(OSError, match="disk full"):
        anchored_append(FailingStore())((), EVENTS[0])
    record = run_with(FailingStore())
    assert record.halted == "audit append failed"
    assert not any(e.type == "effect_executed" for e in record.events)


@pytest.mark.invariant("I1")
def test_inner_append_failure_leaves_the_anchor() -> None:
    store = AnchorStore()

    def inner(chain: Sequence[AuditEntry], event: Event) -> tuple[AuditEntry, ...]:
        if len(chain) == 2:
            raise OSError("log write failed")
        return append(chain, event)

    wrapper = anchored_append(store, inner)
    chain = feed(wrapper, EVENTS[:2])
    with pytest.raises(OSError, match="log write failed"):
        wrapper(chain, EVENTS[2])
    assert store.get(EVENTS[0].run_id) == Anchor(
        run_id=EVENTS[0].run_id, head=chain[-1].hash, length=2
    )


@pytest.mark.invariant("I1")
def test_truncation_is_detected() -> None:
    store = AnchorStore()
    chain = run_with(store).chain
    truncated = chain[:-1]
    assert verify_chain(truncated)
    result = verify_against_anchor(store, RUN_ID, truncated)
    assert not result.ok
    assert result.reason == "length mismatch"
    assert result.first_bad_index == len(truncated)


@pytest.mark.invariant("I1")
def test_tampering_is_detected() -> None:
    store = AnchorStore()
    chain = run_with(store).chain
    edited = chain[1].event.model_copy(update={"seq": chain[1].event.seq + 100})
    tampered = (chain[0], chain[1].model_copy(update={"event": edited}), *chain[2:])
    result = verify_against_anchor(store, RUN_ID, tampered)
    assert not result.ok
    assert result.reason == "hash mismatch"
    assert result.first_bad_index == 1


@pytest.mark.invariant("I1")
def test_untruncated_chain_verifies() -> None:
    store = AnchorStore()
    chain = run_with(store).chain
    assert len(chain) > 2
    assert verify_against_anchor(store, RUN_ID, chain).ok


@pytest.mark.invariant("I1")
def test_no_anchor_reports_it() -> None:
    result = verify_against_anchor(AnchorStore(), "unknown", ())
    assert (result.ok, result.first_bad_index, result.reason) == (False, None, "no anchor")


@pytest.mark.invariant("I6")
def test_two_runs_do_not_share_anchors() -> None:
    store = AnchorStore()
    wrapper = anchored_append(store)
    first = wrapper((), EVENTS[0])
    other = EVENTS[0].model_copy(update={"run_id": "run-other"})
    second = wrapper(wrapper((), other), EVENTS[1].model_copy(update={"run_id": "run-other"}))
    assert store.get(EVENTS[0].run_id) == Anchor(
        run_id=EVENTS[0].run_id, head=first[-1].hash, length=1
    )
    assert store.get("run-other") == Anchor(run_id="run-other", head=second[-1].hash, length=2)


@pytest.mark.invariant("I6")
def test_thread_safety() -> None:
    store = AnchorStore()
    errors: list[BaseException] = []

    def work(index: int) -> None:
        try:
            for length in range(1, 21):
                store.record(f"run-{index}", f"{index:064x}", length)
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    for index in range(8):
        assert store.get(f"run-{index}") == Anchor(
            run_id=f"run-{index}", head=f"{index:064x}", length=20
        )


@pytest.mark.invariant("I6")
def test_anchor_route() -> None:
    store = AnchorStore()
    chain = run_with(store).chain
    client = TestClient(create_app(event_delay=0, anchors=store))
    response = client.get(f"/runs/{RUN_ID}/anchor")
    assert response.status_code == 200
    assert response.json() == {"run_id": RUN_ID, "head": chain[-1].hash, "length": len(chain)}
    missing = client.get("/runs/nope/anchor")
    assert (missing.status_code, missing.json()) == (404, {"detail": "no anchor for this run"})
    operation = client.get("/openapi.json").json()["paths"]["/runs/{run_id}/anchor"]["get"]
    assert operation["operationId"] == "getAnchor"


@pytest.mark.invariant("I6")
def test_default_app_has_an_in_memory_store() -> None:
    client = TestClient(create_app(event_delay=0))
    assert client.get("/runs/anything/anchor").status_code == 404


@pytest.mark.invariant("I1")
def test_replay_cli_values_match() -> None:
    """`notary replay` prints `chain: OK head=<head> length=<n>` from `verify_chain_detailed`."""
    store = AnchorStore()
    chain = run_with(store).chain
    anchor = store.get(RUN_ID)
    assert anchor is not None
    assert (anchor.head, anchor.length) == (chain[-1].hash, len(chain))
    assert verify_chain_detailed(chain, expected_length=anchor.length, expected_head=anchor.head).ok
    assert verify_chain_detailed((), expected_head=GENESIS_HASH).ok


@pytest.mark.invariant("I1")
def test_a_reused_run_id_restarts_its_anchor() -> None:
    """Golden run ids repeat: a second run under one id must not hit `cannot move backwards`."""
    store = AnchorStore()
    wrapper = anchored_append(store)
    first = feed(wrapper, EVENTS[:5])
    assert store.get(EVENTS[0].run_id) == Anchor(
        run_id=EVENTS[0].run_id, head=first[-1].hash, length=5
    )
    second = feed(wrapper, EVENTS[:3])
    assert store.get(EVENTS[0].run_id) == Anchor(
        run_id=EVENTS[0].run_id, head=second[-1].hash, length=3
    )
    with pytest.raises(ValueError, match="anchor cannot move backwards"):
        store.record(EVENTS[0].run_id, HEAD_A, 2)
    with pytest.raises(ValueError, match="invalid anchor"):
        store.restart("r1", "nope")
