"""Tamper-evident audit hash chain over `Event`s.

Each entry hashes `prev_hash`, its `index` and the canonical JSON of its event; there are no
timestamps in hashed content (`Event` already carries `run_id` and `seq`).
"""

from collections.abc import Sequence

from notary_core.canon import canonical_json, sha256_hex
from notary_core.models.audit import AuditEntry
from notary_core.models.events import Event
from notary_core.models.labels import NotaryModel

GENESIS_HASH: str = "0" * 64
"""`prev_hash` of the first entry, and the head of an empty chain."""


class VerifyResult(NotaryModel):
    """Not exported to the JSON Schema: deliberately absent from `notary_core.models.__all__`."""

    ok: bool
    first_bad_index: int | None
    reason: str
    """"" when ok; else "index mismatch" | "prev_hash mismatch" | "hash mismatch" |
    "length mismatch" | "head mismatch"."""


def entry_hash(prev_hash: str, index: int, event: Event) -> str:
    """Includes `index`, so identical events at different positions hash differently."""
    payload = canonical_json(event.model_dump(mode="json"))
    return sha256_hex(f"{prev_hash}\n{index}\n{payload}")


def append(chain: Sequence[AuditEntry], event: Event) -> tuple[AuditEntry, ...]:
    """Return a new chain with `event` appended; the input is never mutated."""
    prev_hash = chain[-1].hash if chain else GENESIS_HASH
    index = len(chain)
    entry = AuditEntry(
        index=index,
        prev_hash=prev_hash,
        hash=entry_hash(prev_hash, index, event),
        event=event,
    )
    return (*chain, entry)


def verify_chain_detailed(
    chain: Sequence[AuditEntry],
    *,
    expected_length: int | None = None,
    expected_head: str | None = None,
) -> VerifyResult:
    """Walk the chain and report the first problem.

    Limitation: the chain proves the integrity of the sequence, not its completeness. Dropping
    entries from the tail leaves a valid chain, so truncation is only detected when the caller
    keeps an anchor outside the log (e.g. the server persists the head hash and length) and passes
    it as `expected_length` / `expected_head`. The head of an empty chain is `GENESIS_HASH`.
    """
    for i, entry in enumerate(chain):
        if entry.index != i:
            return VerifyResult(ok=False, first_bad_index=i, reason="index mismatch")
        if entry.prev_hash != (GENESIS_HASH if i == 0 else chain[i - 1].hash):
            return VerifyResult(ok=False, first_bad_index=i, reason="prev_hash mismatch")
        if entry.hash != entry_hash(entry.prev_hash, entry.index, entry.event):
            return VerifyResult(ok=False, first_bad_index=i, reason="hash mismatch")
    if expected_length is not None and len(chain) != expected_length:
        return VerifyResult(
            ok=False, first_bad_index=min(len(chain), expected_length), reason="length mismatch"
        )
    if expected_head is not None:
        head = chain[-1].hash if chain else GENESIS_HASH
        if head != expected_head:
            return VerifyResult(
                ok=False, first_bad_index=max(len(chain) - 1, 0), reason="head mismatch"
            )
    return VerifyResult(ok=True, first_bad_index=None, reason="")


def verify_chain(chain: Sequence[AuditEntry]) -> bool:
    return verify_chain_detailed(chain).ok
