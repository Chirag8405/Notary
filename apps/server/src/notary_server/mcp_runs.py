"""Runs of the MCP proxy, read from the audit chains it writes (`mode=mcp`).

The proxy writes `<run_id>.chain.jsonl` (one `AuditEntry` per line, written before the effect) and
`<run_id>.anchor.json` into a directory (`notary-mcp-proxy --audit-dir`). The server only reads
that directory, never writes to it, and no network path leads from the proxy to the server.

`McpRunsSource` replays a chain from index 0 and then follows it. Nothing reaches the client before
it is verified: every entry must be the next index, carry the previous entry's hash, hash to
`entry_hash(prev_hash, index, event)` and belong to the run named by its file. A complete line that
does not parse, a failed check, a file that shrank or a line that grows past `MAX_LINE_BYTES`
ends the stream with `RunUnavailableError(CLOSE_CHAIN_BROKEN, "chain broken")` after the last
valid event.
A last line without its newline is a write in progress and is waited for, not corruption.

The hash chain proves order and integrity, not completeness, and nothing here can tell a proxy that
crashed in the middle of a line from one that is slow: such a run stays open ("live") until the
socket closes. When an `AnchorStore` is given, the head of every verified entry is also recorded
there, which is a second copy of the anchor kept outside the directory; a later read of the same
run must then reach the same head at the same length. It does not detect a file cut short.

A run id is `mcp-<12 hex>` (the proxy's format) and is checked before it is used in any path.

`McpApprovals` is the one thing here that talks to the proxy: it forwards an approve or reject from
the endorsement card to the run's control socket (see its docstring). It never resolves a card; the
card closes only when the chain says so.
"""

import json
import os
import re
import socket
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Annotated

from pydantic import Field, ValidationError

from notary_core.audit import GENESIS_HASH, entry_hash
from notary_core.models import (
    AuditEntry,
    Command,
    EndorsementDecisionCommand,
    Event,
    NotaryModel,
    Sha256Hex,
)
from notary_server.anchors import AnchorStore
from notary_server.commands import (
    CLOSE_COMMAND_CONFLICT,
    CLOSE_UNSUPPORTED_COMMAND,
    CommandContext,
    CommandHandler,
    CommandRejected,
)
from notary_server.sources import RunRequest, RunUnavailableError

CLOSE_CHAIN_BROKEN = 4503
RUN_ID = re.compile(r"mcp-[0-9a-f]{12}")
CHAIN_SUFFIX = ".chain.jsonl"
ANCHOR_SUFFIX = ".anchor.json"
CONTROL_SUFFIX = ".control.json"
MAX_LINE_BYTES = 4 * 1024 * 1024
"""A line longer than this is not an audit entry: the writer's lines are far smaller."""
MAX_LISTED_RUNS = 100
CONTROL_TIMEOUT_SECONDS = 5.0
"""How long a connect, a write or a read on a control socket may take."""
FORWARDED_OPS = frozenset({"approve", "reject"})
"""The only ops the server ever sends to a control socket."""
REASON_NOT_SUPPORTED = "decision not supported on mcp runs"
REASON_NOT_DELIVERED = "approval not delivered"
REASON_NOT_ACCEPTED = "approval not accepted"
_CHUNK_BYTES = 64 * 1024
_MAX_ANCHOR_BYTES = 4096
_MAX_CONTROL_FILE_BYTES = 4096
_MAX_CONTROL_REPLY_BYTES = 65536


class McpRunInfo(NotaryModel):
    run_id: str
    length: Annotated[int, Field(ge=0)]
    """Entries in the chain, from the anchor file the proxy keeps next to it."""
    head: Sha256Hex | None
    """The hash of the last entry, from the anchor file; None for an empty chain."""
    finished: bool
    """Whether the last entry of the chain is `run_finished`."""


class McpRunList(NotaryModel):
    runs: tuple[McpRunInfo, ...]


class _AnchorFile(NotaryModel):
    """The proxy's `<run_id>.anchor.json`, read here without importing the proxy."""

    run_id: str
    length: Annotated[int, Field(ge=0)]
    head: Sha256Hex | None


class _ChainBrokenError(Exception):
    pass


def _chain_broken() -> RunUnavailableError:
    return RunUnavailableError(CLOSE_CHAIN_BROKEN, "chain broken")


def _inside(directory: Path, name: str) -> Path | None:
    """`directory/name` when it is a regular file that really lives in `directory`, else None.

    `name` is built from a validated run id, so it has no separator; a symlink is refused anyway.
    """
    path = directory / name
    if path.is_symlink() or not path.is_file():
        return None
    if path.resolve().parent != directory.resolve():
        return None
    return path


def _read_anchor(path: Path) -> _AnchorFile | None:
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_ANCHOR_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _MAX_ANCHOR_BYTES:
        return None
    try:
        return _AnchorFile.model_validate_json(raw)
    except ValidationError:
        return None


def _last_event_type(path: Path) -> str | None:
    """The event type of the chain's last complete line, or None when it cannot be read."""
    try:
        with path.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            window = min(size, MAX_LINE_BYTES)
            handle.seek(size - window)
            tail = handle.read(window)
    except OSError:
        return None
    last = tail.rstrip(b"\n")
    start = last.rfind(b"\n")
    if start < 0 and window < size:
        return None
    try:
        entry = AuditEntry.model_validate_json(last[start + 1 :])
    except ValidationError:
        return None
    return entry.event.type


def list_mcp_runs(directory: Path) -> tuple[McpRunInfo, ...]:
    """The runs whose anchor and chain files are in `directory`, newest first.

    Newest is by the modification time of the anchor file, which the proxy rewrites after every
    entry, so it is the last activity. A file that is not a valid anchor of its own run is skipped.
    A missing directory (no proxy has run yet) lists nothing.
    """
    try:
        names = sorted(name for name in os.listdir(directory) if name.endswith(ANCHOR_SUFFIX))
    except OSError:
        return ()
    found: list[tuple[int, str, McpRunInfo]] = []
    for name in names:
        run_id = name.removesuffix(ANCHOR_SUFFIX)
        if RUN_ID.fullmatch(run_id) is None:
            continue
        anchor_path = _inside(directory, name)
        chain_path = _inside(directory, run_id + CHAIN_SUFFIX)
        if anchor_path is None or chain_path is None:
            continue
        anchor = _read_anchor(anchor_path)
        if anchor is None or anchor.run_id != run_id:
            continue
        try:
            modified = anchor_path.stat().st_mtime_ns
        except OSError:
            continue
        info = McpRunInfo(
            run_id=run_id,
            length=anchor.length,
            head=anchor.head,
            finished=_last_event_type(chain_path) == "run_finished",
        )
        found.append((modified, run_id, info))
    found.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return tuple(info for _, _, info in found[:MAX_LISTED_RUNS])


class McpRunsSource:
    """A `RunSource` over a directory of proxy audit chains. `request.scenario` is the run id.

    `poll` is the short wait between two looks at a chain that has nothing new; tests pass a
    no-op. When there is nothing new the iterator yields `None` after each wait (see
    `RunSource.events`), so a step is always short and a closed socket is noticed within one poll.
    """

    def __init__(
        self,
        directory: Path,
        *,
        poll: Callable[[], None],
        anchors: AnchorStore | None = None,
    ) -> None:
        self._directory = directory
        self._poll = poll
        self._anchors = anchors

    def events(self, request: RunRequest) -> Iterator[Event | None]:
        """Raise `KeyError` for an id that is not a proxy run id or has no chain file."""
        run_id = request.scenario
        if RUN_ID.fullmatch(run_id) is None:
            raise KeyError(run_id)
        path = _inside(self._directory, run_id + CHAIN_SUFFIX)
        if path is None:
            raise KeyError(run_id)
        return self._follow(run_id, path)

    def _follow(self, run_id: str, path: Path) -> Iterator[Event | None]:
        index = 0
        prev_hash = GENESIS_HASH
        buffer = b""
        with path.open("rb") as handle:
            while True:
                newline = buffer.find(b"\n")
                if newline >= 0:
                    line, buffer = buffer[:newline], buffer[newline + 1 :]
                    try:
                        entry = self._verified(run_id, index, prev_hash, line)
                    except _ChainBrokenError:
                        raise _chain_broken() from None
                    index, prev_hash = index + 1, entry.hash
                    yield entry.event
                    if entry.event.type == "run_finished":
                        return
                    continue
                if len(buffer) > MAX_LINE_BYTES:
                    raise _chain_broken()
                chunk = handle.read(_CHUNK_BYTES)
                if chunk:
                    buffer += chunk
                    continue
                if os.fstat(handle.fileno()).st_size < handle.tell():
                    raise _chain_broken()  # the file shrank under us
                self._poll()
                yield None

    def _verified(self, run_id: str, index: int, prev_hash: str, line: bytes) -> AuditEntry:
        try:
            entry = AuditEntry.model_validate_json(line)
        except ValidationError:
            raise _ChainBrokenError from None
        if (
            entry.index != index
            or entry.prev_hash != prev_hash
            or entry.hash != entry_hash(prev_hash, index, entry.event)
            or entry.event.run_id != run_id
        ):
            raise _ChainBrokenError
        self._anchor(run_id, entry)
        return entry

    def _anchor(self, run_id: str, entry: AuditEntry) -> None:
        """Keep a second copy of the head, and refuse a chain that disagrees with it."""
        if self._anchors is None:
            return
        length = entry.index + 1
        stored = self._anchors.get(run_id)
        if stored is not None and stored.length == length and stored.head != entry.hash:
            raise _ChainBrokenError
        if stored is None or stored.length < length:
            self._anchors.record(run_id, entry.hash, length)


# -- approvals -------------------------------------------------------------------------------------


class _ControlFile(NotaryModel):
    """The proxy's `<run_id>.control.json`, read here without importing the proxy."""

    socket: Annotated[str, Field(min_length=1, max_length=4096)]


class _ControlReply(NotaryModel):
    ok: bool
    error: str | None = None


def _unix_connect(path: Path) -> socket.socket:
    """Connect to a Unix socket with a bounded wait. The caller closes it."""
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(CONTROL_TIMEOUT_SECONDS)
        connection.connect(str(path))
    except BaseException:
        connection.close()
        raise
    return connection


class McpApprovals:
    """Forwards the card's approve or reject of an MCP proxy run to that run's control socket.

    The proxy announces the socket in `DIR/<run_id>.control.json` (`{"socket": "<abs path>"}`, next
    to the chain). Nothing in that file is trusted: the run id is checked against `mcp-<12 hex>`
    before it is a path, the file must be a regular file (no link) of the audit directory, and the
    socket path in it must be absolute and, once links are resolved, lie inside `control_directory`
    (the directory the proxy's `--control` sockets live in). Anything else is refused and nothing
    is connected to.

    `forward` blocks on a socket, so the app runs the handler off the event loop. It only forwards
    `approve` and `reject` and never resolves a card or reports success to the page: a card closes
    when the chain shows the proxy's second `decision_made` or a block. `use_nearest` is refused,
    the proxy has no such path. A refusal by the proxy (`ok: false`: unknown or already decided id)
    or an unreachable socket is a `CommandRejected` with a fixed reason; the proxy's own text is
    never relayed.

    Whether approvals are on at all, and whether the client is on this machine, is decided before
    this handler is registered on a socket (`create_app`).
    """

    def __init__(
        self,
        directory: Path,
        *,
        control_directory: Path,
        connect: Callable[[Path], socket.socket] = _unix_connect,
    ) -> None:
        self._directory = directory
        self._control_directory = control_directory
        self._connect = connect

    def handler(self) -> CommandHandler:
        """For `CommandRouter.register("endorsement_decision", ...)`."""

        def handle(command: Command, context: CommandContext) -> None:
            if not isinstance(command, EndorsementDecisionCommand):
                raise CommandRejected(
                    CLOSE_UNSUPPORTED_COMMAND, "command not supported on this socket"
                )
            if command.decision == "use_nearest":
                raise CommandRejected(CLOSE_UNSUPPORTED_COMMAND, REASON_NOT_SUPPORTED)
            self.forward(command.run_id, command.endorsement_id, command.decision)

        return handle

    def control_socket(self, run_id: str) -> Path | None:
        """The validated control socket of a run, or None when it is missing or not acceptable."""
        if RUN_ID.fullmatch(run_id) is None:
            return None
        path = _inside(self._directory, run_id + CONTROL_SUFFIX)
        if path is None:
            return None
        try:
            with path.open("rb") as handle:
                raw = handle.read(_MAX_CONTROL_FILE_BYTES + 1)
        except OSError:
            return None
        if len(raw) > _MAX_CONTROL_FILE_BYTES:
            return None
        try:
            announced = _ControlFile.model_validate_json(raw).socket
        except ValidationError:
            return None
        if "\0" in announced or not os.path.isabs(announced):
            return None
        resolved = Path(os.path.realpath(announced))
        if not resolved.is_relative_to(self._control_directory.resolve()):
            return None
        return resolved

    def forward(self, run_id: str, endorsement_id: str, decision: str) -> None:
        """Send `approve` or `reject` to the run's control socket (blocking).

        Raises `CommandRejected` when the socket is not acceptable or cannot be reached, or when
        the proxy does not accept the decision.
        """
        if decision not in FORWARDED_OPS:
            # The control socket also takes `user_prompt` (the user's own words, trusted): nothing
            # but a card decision may ever be sent from here, whatever the caller passes.
            raise CommandRejected(CLOSE_UNSUPPORTED_COMMAND, REASON_NOT_SUPPORTED)
        target = self.control_socket(run_id)
        if target is None:
            raise CommandRejected(CLOSE_COMMAND_CONFLICT, REASON_NOT_DELIVERED)
        message = {"op": decision, "endorsement_id": endorsement_id}
        try:
            connection = self._connect(target)
            try:
                connection.settimeout(CONTROL_TIMEOUT_SECONDS)
                with connection.makefile("rwb") as stream:
                    stream.write(json.dumps(message).encode("utf-8") + b"\n")
                    stream.flush()
                    line = stream.readline(_MAX_CONTROL_REPLY_BYTES + 1)
            finally:
                connection.close()
        except OSError:
            raise CommandRejected(CLOSE_COMMAND_CONFLICT, REASON_NOT_DELIVERED) from None
        try:
            reply = _ControlReply.model_validate_json(line)
        except ValidationError:
            raise CommandRejected(CLOSE_COMMAND_CONFLICT, REASON_NOT_DELIVERED) from None
        if not reply.ok:
            raise CommandRejected(CLOSE_COMMAND_CONFLICT, REASON_NOT_ACCEPTED)
