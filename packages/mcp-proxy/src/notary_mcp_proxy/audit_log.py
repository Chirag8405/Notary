"""The proxy's durable audit log: one hash-chain file per run, written before the effect.

`durable_append(log)` is the Gateway's `audit_append`: every entry (an `AuditEntry`, one JSON line)
is flushed and fsynced BEFORE the Gateway goes on, so `decision_made` is on disk before the tool
runs (I1). A failed write raises; the Gateway then halts (`audit append failed`) and runs no tool.
Once a write has failed the log refuses every later write: the file may end in a partial line, and
a verifier must see the failure, not a chain that quietly continues.

The anchor file next to the chain holds its length and head after every append. It is replaced
atomically (tmp + `os.replace`), so it is always valid JSON. A hash chain proves order and
integrity, not completeness: dropping entries from the end leaves a valid chain, and only an anchor
kept elsewhere (the stderr line at exit, a copy the user keeps) detects that. An anchor next to
the log does not stop someone who can rewrite both files.
"""

import os
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import IO, Annotated

from pydantic import Field

from notary_core.audit import append
from notary_core.models import AuditEntry, Event, NotaryModel, Sha256Hex
from notary_mcp_proxy.gateway import AuditAppend

CHAIN_SUFFIX = ".chain.jsonl"
ANCHOR_SUFFIX = ".anchor.json"
_SAFE_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

Sync = Callable[[int], None]
"""Makes a file descriptor's data durable (`os.fsync`); tests replace it to simulate a failure."""


class AuditWriteError(Exception):
    """The log could not take an entry. The message is constant; the cause is chained."""


class ChainAnchor(NotaryModel):
    run_id: str
    length: Annotated[int, Field(ge=0)]
    head: Sha256Hex | None
    """The hash of the last entry; None for an empty chain."""


def _fsync_directory(directory: Path) -> None:
    """Make a created or renamed file's directory entry durable (best effort; not on Windows)."""
    try:
        handle = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(handle)
    except OSError:
        pass
    finally:
        os.close(handle)


class RunLog:
    def __init__(self, directory: Path, run_id: str, *, sync: Sync = os.fsync) -> None:
        """Creates `directory/<run_id>.chain.jsonl` (it must not exist) and its anchor file."""
        if _SAFE_RUN_ID.fullmatch(run_id) is None:
            raise ValueError("run id is not a safe file name")
        directory.mkdir(parents=True, exist_ok=True)
        self._run_id = run_id
        self._sync = sync
        self._chain_path = directory / f"{run_id}{CHAIN_SUFFIX}"
        self._anchor_path = directory / f"{run_id}{ANCHOR_SUFFIX}"
        self._length = 0
        self._head: str | None = None
        self._failed = False
        self._out: IO[str] | None = self._chain_path.open("x", encoding="utf-8")
        try:
            self._write_anchor()
            _fsync_directory(directory)
        except BaseException:
            self.close()
            raise

    @property
    def chain_path(self) -> Path:
        return self._chain_path

    @property
    def anchor_path(self) -> Path:
        return self._anchor_path

    @property
    def anchor(self) -> ChainAnchor:
        return ChainAnchor(run_id=self._run_id, length=self._length, head=self._head)

    def write(self, entry: AuditEntry) -> None:
        """Append one line and make it durable, then move the anchor. Raises `AuditWriteError`."""
        if self._failed or self._out is None:
            raise AuditWriteError("the audit log is closed or failed")
        if entry.index != self._length:
            self._failed = True
            raise AuditWriteError("the entry does not follow the log")
        try:
            # One write call, so a failure leaves at most one partial line at the end.
            self._out.write(entry.model_dump_json() + "\n")
            self._out.flush()
            self._sync(self._out.fileno())
            self._length = entry.index + 1
            self._head = entry.hash
            self._write_anchor()
        except (OSError, ValueError) as failure:
            self._failed = True
            raise AuditWriteError("the audit log could not be written") from failure

    def close(self) -> None:
        out, self._out = self._out, None
        if out is not None:
            out.close()

    def _write_anchor(self) -> None:
        temporary = self._anchor_path.with_name(self._anchor_path.name + ".tmp")
        with temporary.open("w", encoding="utf-8") as out:
            out.write(self.anchor.model_dump_json() + "\n")
            out.flush()
            self._sync(out.fileno())
        os.replace(temporary, self._anchor_path)


def durable_append(log: RunLog, inner: AuditAppend = append) -> AuditAppend:
    """An `AuditAppend` that writes the new entry to `log` before returning the new chain."""

    def durable(chain: Sequence[AuditEntry], event: Event) -> tuple[AuditEntry, ...]:
        new = inner(chain, event)
        log.write(new[-1])
        return new

    return durable
