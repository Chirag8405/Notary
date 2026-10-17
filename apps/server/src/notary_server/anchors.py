"""Audit anchors: the chain head and length, stored outside the log.

A hash chain proves the integrity of a sequence, not its completeness: dropping entries from the
tail leaves a valid chain. The anchor is an independent copy of (head, length) that a verifier
checks the chain against.
"""

import re
import sqlite3
import threading
from collections.abc import Sequence

from notary_core.audit import VerifyResult, append, verify_chain_detailed
from notary_core.models import AuditEntry, Event, NotaryModel, Sha256Hex
from notary_world.executor import AuditAppend

_HEAD = re.compile(r"[0-9a-f]{64}")


class Anchor(NotaryModel):
    run_id: str
    head: Sha256Hex
    """`GENESIS_HASH` for an empty chain, otherwise the hash of the last entry."""
    length: int
    """Number of entries."""


class AnchorStore:
    """One SQLite table, one row per run. No timestamps; every statement is parameterized."""

    def __init__(self, path: str = ":memory:") -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        with self._lock, self._db:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS anchors "
                "(run_id TEXT PRIMARY KEY, head TEXT NOT NULL, length INTEGER NOT NULL)"
            )

    def record(self, run_id: str, head: str, length: int) -> None:
        """Upsert the anchor of a run. An anchor only grows."""
        if _HEAD.fullmatch(head) is None or length < 0:
            raise ValueError("invalid anchor")
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT length FROM anchors WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is not None and length < row[0]:
                raise ValueError("anchor cannot move backwards")
            self._db.execute(
                "INSERT INTO anchors (run_id, head, length) VALUES (?, ?, ?) "
                "ON CONFLICT(run_id) DO UPDATE SET head = excluded.head, length = excluded.length",
                (run_id, head, length),
            )

    def restart(self, run_id: str, head: str) -> None:
        """A new run starts under a reused id (golden run ids repeat): its anchor starts at one
        entry. Only the first entry of a chain may do this; a longer chain goes through `record`."""
        if _HEAD.fullmatch(head) is None:
            raise ValueError("invalid anchor")
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO anchors (run_id, head, length) VALUES (?, ?, 1) "
                "ON CONFLICT(run_id) DO UPDATE SET head = excluded.head, length = 1",
                (run_id, head),
            )

    def get(self, run_id: str) -> Anchor | None:
        with self._lock:
            row = self._db.execute(
                "SELECT head, length FROM anchors WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            return None
        return Anchor(run_id=run_id, head=row[0], length=row[1])

    def close(self) -> None:
        with self._lock:
            self._db.close()


def anchored_append(store: AnchorStore, inner: AuditAppend | None = None) -> AuditAppend:
    """An `AuditAppend` that records the new head and length after every successful append.

    A failure of `inner` or of the anchor write propagates, so the engine halts and no effect
    runs (write-ahead audit). If the process dies between the two steps the anchor leads the
    chain by one entry, which a verification reports as `length mismatch` (the safe direction).
    """
    step = append if inner is None else inner

    def anchored(chain: Sequence[AuditEntry], event: Event) -> tuple[AuditEntry, ...]:
        new = step(chain, event)
        if len(new) == 1:
            store.restart(event.run_id, new[-1].hash)
        else:
            store.record(event.run_id, new[-1].hash, len(new))
        return new

    return anchored


def verify_against_anchor(
    store: AnchorStore, run_id: str, chain: Sequence[AuditEntry]
) -> VerifyResult:
    anchor = store.get(run_id)
    if anchor is None:
        return VerifyResult(ok=False, first_bad_index=None, reason="no anchor")
    return verify_chain_detailed(chain, expected_length=anchor.length, expected_head=anchor.head)
