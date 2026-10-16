"""Audit hash chain: append, verify_chain and tamper detection."""

from hypothesis import given
from hypothesis import strategies as st

from notary_core import models
from notary_core.audit import (
    GENESIS_HASH,
    append,
    entry_hash,
    verify_chain,
    verify_chain_detailed,
)
from notary_core.models import AuditEntry, Event, RunFinished

HEX = "0123456789abcdef"


def _event(seq: int, summary: str = "done") -> RunFinished:
    return RunFinished(
        type="run_finished",
        run_id="run-1",
        lane="notary",
        seq=seq,
        outcome="completed",
        summary=f"{summary} {seq}",
    )


def _chain(length: int = 5) -> tuple[AuditEntry, ...]:
    chain: tuple[AuditEntry, ...] = ()
    for seq in range(length):
        chain = append(chain, _event(seq))
    return chain


def _forged(prev: AuditEntry, index: int, event: Event) -> AuditEntry:
    """An entry with a correctly recomputed own hash."""
    return AuditEntry(
        index=index,
        prev_hash=prev.hash,
        hash=entry_hash(prev.hash, index, event),
        event=event,
    )


# covers: model
def test_empty_chain_is_valid() -> None:
    assert verify_chain(()) is True
    assert verify_chain_detailed(()).reason == ""


# covers: model
def test_append_builds_a_valid_chain() -> None:
    chain = _chain(5)
    result = verify_chain_detailed(chain)
    assert [entry.index for entry in chain] == [0, 1, 2, 3, 4]
    assert all(chain[i].prev_hash == chain[i - 1].hash for i in range(1, 5))
    assert (result.ok, result.first_bad_index, result.reason) == (True, None, "")


# covers: model
def test_first_entry_links_to_genesis() -> None:
    assert _chain(1)[0].prev_hash == GENESIS_HASH == "0" * 64


# covers: model
def test_modified_event_is_detected() -> None:
    chain = _chain()
    tampered = (*chain[:3], chain[3].model_copy(update={"event": _event(3, "forged")}), chain[4])
    result = verify_chain_detailed(tampered)
    assert (result.ok, result.first_bad_index, result.reason) == (False, 3, "hash mismatch")


# covers: model
def test_deleted_middle_entry_is_detected() -> None:
    chain = _chain()
    result = verify_chain_detailed(chain[:2] + chain[3:])
    assert (result.ok, result.first_bad_index, result.reason) == (False, 2, "index mismatch")


# covers: model
def test_reordered_entries_are_detected() -> None:
    chain = _chain()
    swapped = (chain[0], chain[2], chain[1], *chain[3:])
    result = verify_chain_detailed(swapped)
    assert (result.ok, result.first_bad_index, result.reason) == (False, 1, "index mismatch")


# covers: model
def test_inserted_entry_is_detected() -> None:
    chain = _chain()
    forged = _forged(chain[1], 2, _event(99, "forged"))
    # Naive insertion: every later entry has the wrong index.
    naive = (*chain[:2], forged, *chain[2:])
    assert verify_chain_detailed(naive).reason == "index mismatch"
    assert verify_chain_detailed(naive).first_bad_index == 3
    # The attacker also renumbers the later entries; their prev_hash still points at the old link.
    renumbered = (
        *chain[:2],
        forged,
        *(entry.model_copy(update={"index": entry.index + 1}) for entry in chain[2:]),
    )
    result = verify_chain_detailed(renumbered)
    assert (result.ok, result.first_bad_index, result.reason) == (False, 3, "prev_hash mismatch")


# covers: model
def test_replaced_entry_with_recomputed_hash_breaks_the_next_link() -> None:
    chain = _chain()
    forged = _forged(chain[1], 2, _event(2, "forged"))
    result = verify_chain_detailed((*chain[:2], forged, *chain[3:]))
    assert (result.ok, result.first_bad_index, result.reason) == (False, 3, "prev_hash mismatch")


# covers: model
def test_truncation_detected_with_expected_length() -> None:
    chain = _chain()
    truncated = chain[:-1]
    assert verify_chain(truncated) is True  # the chain alone cannot show truncation
    result = verify_chain_detailed(truncated, expected_length=5)
    assert (result.ok, result.first_bad_index, result.reason) == (False, 4, "length mismatch")
    assert verify_chain_detailed(chain, expected_length=5).ok is True


# covers: model
def test_head_mismatch_detected() -> None:
    chain = _chain()
    assert verify_chain_detailed(chain, expected_head=chain[-1].hash).ok is True
    result = verify_chain_detailed(chain, expected_head=chain[-2].hash)
    assert (result.ok, result.first_bad_index, result.reason) == (False, 4, "head mismatch")
    assert verify_chain_detailed((), expected_head=GENESIS_HASH).ok is True
    assert verify_chain_detailed((), expected_head=chain[0].hash).reason == "head mismatch"
    assert verify_chain_detailed(chain[:-1], expected_head=chain[-1].hash).reason == "head mismatch"


# covers: model
def test_append_does_not_mutate_input() -> None:
    chain = _chain(3)
    snapshot = tuple(entry.model_dump_json() for entry in chain)
    longer = append(chain, _event(3))
    assert len(chain) == 3
    assert len(longer) == 4
    assert tuple(entry.model_dump_json() for entry in chain) == snapshot
    assert longer[:3] == chain


# covers: model
def test_same_events_same_hashes() -> None:
    first, second = _chain(), _chain()
    assert [e.model_dump_json() for e in first] == [e.model_dump_json() for e in second]
    # Identical events at different positions hash differently (index is hashed).
    event = _event(0)
    assert entry_hash(GENESIS_HASH, 0, event) != entry_hash(GENESIS_HASH, 1, event)


# covers: model
def test_entry_hash_golden_vector() -> None:
    # Pins the hash input format: f"{prev_hash}\n{index}\n{canonical_json(event)}".
    assert entry_hash(GENESIS_HASH, 0, _event(0)) == _chain(1)[0].hash
    assert _chain(1)[0].hash == "914e8f1c1b9fb9ac5a64c71712b6f3f7a2f92f816fb6d147527652bb2fdfe049"


def _different_hex(old: str) -> st.SearchStrategy[str]:
    return st.text(alphabet=HEX, min_size=64, max_size=64).filter(lambda h: h != old)


def _tampered_value(entry: AuditEntry, field: str) -> st.SearchStrategy[object]:
    if field == "index":
        return st.integers(min_value=0, max_value=50).filter(lambda n: n != entry.index)
    if field == "event":
        return (
            st.integers(min_value=0, max_value=50)
            .filter(lambda n: n != entry.event.seq)
            .map(lambda n: entry.event.model_copy(update={"seq": n}))
        )
    return _different_hex(entry.prev_hash if field == "prev_hash" else entry.hash)


# covers: model
@given(
    st.integers(min_value=0, max_value=4),
    st.sampled_from(("index", "prev_hash", "hash", "event")),
    st.data(),
)
def test_random_tampering_is_always_detected(
    position: int, field: str, data: st.DataObject
) -> None:
    chain = _chain()
    entry = chain[position]
    value = data.draw(_tampered_value(entry, field))
    tampered = entry.model_copy(update={field: value})
    assert verify_chain((*chain[:position], tampered, *chain[position + 1 :])) is False


# covers: model
def test_chain_helpers_are_not_schema_exports() -> None:
    assert "VerifyResult" not in models.__all__
    assert "verify_chain" not in models.__all__
