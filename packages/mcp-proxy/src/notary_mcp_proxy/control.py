"""The control socket: the channel on which the USER approves or rejects an escalated call, and
the channel on which the user's own prompt reaches the proxy.

It is a Unix domain socket, never an MCP tool, prompt or resource, so the agent cannot reach it
through the protocol. The directory is owned by the user with mode 0700 and the socket has mode
0600; on Linux every connection is also checked with `SO_PEERCRED` (same user id). The limit is
stated in docs/threat-model.md: an agent that has a SHELL runs as the same user and can call the
CLI. The guard hook (`notary-mcp-proxy hook pre-tool-use`) denies the shell for that reason.

Protocol: one JSON object per line, one answer per line.

    {"op": "pending"}                                  -> {"pending": [{...}, ...]}
    {"op": "approve" | "reject", "endorsement_id": ..} -> {"ok": true} | {"ok": false, "error": ..}

    {"op": "user_prompt", "prompt": ".."}              -> {"ok": true, "value_id": "request.<n>"}
                                                          | {"ok": false, "error": ..}

The server thread only records a choice on the `ApprovalDesk`. It never touches the Gateway: the
worker thread that owns the Gateway applies the choice. A `user_prompt` is queued the same way
(`PromptSink`, see `Dispatcher.submit_user_prompt`) and the worker stores it as a trusted value.
The op is for the Claude Code `UserPromptSubmit` hook (`notary-mcp-proxy hook user-prompt-submit`);
there is no MCP path to it, and the limit of the socket (the same user can reach it) is stated in
docs/threat-model.md.
"""

import contextlib
import json
import os
import socket
import stat
import struct
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from notary_core.models import NotaryModel
from notary_mcp_proxy.approvals import ApprovalDesk, Choice, printable
from notary_mcp_proxy.client import diagnostic
from notary_mcp_proxy.jsonrpc import JsonObject, as_object, as_str

DEFAULT_DIRECTORY = Path(".notary") / "mcp-control"
MAX_LINE = 65536
"""A request longer than this is refused."""
CONNECTION_TIMEOUT = 10.0
"""Seconds a connected client may stay silent before it is dropped."""
CLIENT_TIMEOUT = 5.0
ERR_UNKNOWN = "unknown or already decided endorsement"
ERR_REQUEST = "bad request"
MAX_PROMPT = 8192
"""Longest prompt, in characters. The JSON line stays under `MAX_LINE` even when every character
is escaped (6 bytes). A longer prompt is refused whole, never cut."""
ERR_PROMPT = "bad prompt"
ERR_PROMPT_REFUSED = "the proxy did not store the prompt"
ERR_PROMPT_OFF = "this proxy does not take prompts"

PromptSink = Callable[[str], str | None]
"""Stores a prompt as a trusted user value and returns its id, or None when it was not stored."""


class UserPromptRequest(NotaryModel):
    """The `user_prompt` op: exactly these two keys, strict types."""

    op: Literal["user_prompt"]
    prompt: str


class ControlError(Exception):
    """The control socket could not be created or reached. The message is safe to print."""


def default_path(run_id: str) -> Path:
    return DEFAULT_DIRECTORY / f"{run_id}.sock"


def prepare_directory(directory: Path) -> None:
    """Create the directory (mode 0700) or check an existing one: ours, not a link, not shared."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(directory)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ControlError(f"{directory} is not a plain directory")
    if info.st_uid != os.getuid():
        raise ControlError(f"{directory} is not owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        os.chmod(directory, 0o700)


def _remove_stale(path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode):
        raise ControlError(f"{path} exists and is not a socket")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(1.0)
        probe.connect(str(path))
    except OSError:
        os.unlink(path)  # nobody listens: a leftover of a run that did not shut down
    else:
        raise ControlError(f"{path} is in use by another proxy")
    finally:
        probe.close()


class ControlServer:
    def __init__(self, desk: ApprovalDesk, path: Path, prompts: PromptSink | None = None) -> None:
        self._desk = desk
        self._prompts = prompts
        self._path = path
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._closing = threading.Event()

    @property
    def path(self) -> Path:
        return self._path

    def start(self) -> None:
        """Bind the socket (mode 0600) and accept connections on a daemon thread."""
        prepare_directory(self._path.parent)
        _remove_stale(self._path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        previous = os.umask(0o177)
        try:
            listener.bind(str(self._path))
        except OSError as failure:
            listener.close()
            raise ControlError(f"cannot bind {self._path}: {failure.strerror}") from failure
        finally:
            os.umask(previous)
        os.chmod(self._path, 0o600)
        listener.listen(8)
        self._socket = listener
        self._thread = threading.Thread(target=self._accept, name="notary-control", daemon=True)
        self._thread.start()

    def close(self) -> None:
        """Stop accepting and remove the socket file."""
        self._closing.set()
        listener = self._socket
        if listener is not None:
            with contextlib.suppress(OSError):
                listener.shutdown(socket.SHUT_RDWR)
            listener.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        with contextlib.suppress(OSError):
            os.unlink(self._path)

    # -- server threads --------------------------------------------------------------------------

    def _accept(self) -> None:
        listener = self._socket
        assert listener is not None
        while not self._closing.is_set():
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            threading.Thread(
                target=self._serve, args=(connection,), name="notary-control-peer", daemon=True
            ).start()

    def _serve(self, connection: socket.socket) -> None:
        with connection:
            if not _same_user(connection):
                diagnostic("control: refused a connection from another user")
                return
            connection.settimeout(CONNECTION_TIMEOUT)
            try:
                with connection.makefile("rwb") as stream:
                    while True:
                        line = stream.readline(MAX_LINE + 1)
                        if not line:
                            return
                        if len(line) > MAX_LINE:
                            reply: JsonObject = {"ok": False, "error": ERR_REQUEST}
                        else:
                            reply = self.handle(line)
                        stream.write(json.dumps(reply).encode("utf-8") + b"\n")
                        stream.flush()
            except OSError:
                return  # a silent or vanished client

    def handle(self, line: bytes) -> JsonObject:
        """The answer to one request line (any thread)."""
        try:
            request = as_object(json.loads(line))
        except ValueError:
            request = None
        if request is None:
            return {"ok": False, "error": ERR_REQUEST}
        op = as_str(request.get("op"))
        if op == "pending":
            return {"pending": [p.model_dump(mode="json") for p in self._desk.pending()]}
        if op in ("approve", "reject"):
            endorsement_id = as_str(request.get("endorsement_id"))
            if endorsement_id is None:
                return {"ok": False, "error": ERR_REQUEST}
            choice: Choice = "approve" if op == "approve" else "reject"
            if self._desk.decide(endorsement_id, choice):
                return {"ok": True}
            return {"ok": False, "error": ERR_UNKNOWN}
        if op == "user_prompt":
            return self._user_prompt(request)
        return {"ok": False, "error": ERR_REQUEST}

    def _user_prompt(self, request: JsonObject) -> JsonObject:
        sink = self._prompts
        if sink is None:
            return {"ok": False, "error": ERR_PROMPT_OFF}
        try:
            prompt = UserPromptRequest.model_validate(request).prompt
        except ValidationError:
            return {"ok": False, "error": ERR_REQUEST}
        if not prompt.strip() or len(prompt) > MAX_PROMPT or not encodable(prompt):
            return {"ok": False, "error": ERR_PROMPT}
        value_id = sink(prompt)
        if value_id is None:
            return {"ok": False, "error": ERR_PROMPT_REFUSED}
        return {"ok": True, "value_id": value_id}


def encodable(text: str) -> bool:
    """Whether the text is valid Unicode (a lone surrogate from a JSON escape is not)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _same_user(connection: socket.socket) -> bool:
    """The peer runs as this user. Without `SO_PEERCRED` the 0700 directory is the only guard."""
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        return True
    size = struct.calcsize("3i")
    _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, option, size))
    return bool(uid == os.getuid())


# -- client (the CLI) ----------------------------------------------------------------------------


def send(path: Path, message: JsonObject, *, timeout: float = CLIENT_TIMEOUT) -> JsonObject:
    """One request, one answer. Raises `ControlError` when the proxy cannot be reached."""
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(timeout)
        try:
            client.connect(str(path))
            with client.makefile("rwb") as stream:
                stream.write(json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n")
                stream.flush()
                line = stream.readline(MAX_LINE + 1)
        except OSError as failure:
            raise ControlError(f"cannot reach the proxy at {path}: {failure}") from failure
    finally:
        client.close()
    try:
        answer = as_object(json.loads(line))
    except ValueError:
        answer = None
    if answer is None:
        raise ControlError(f"the proxy at {path} sent no usable answer")
    return answer


def find_socket(directory: Path = DEFAULT_DIRECTORY) -> Path:
    """The one control socket in `directory`, for `--control` left out."""
    found = sorted(directory.glob("*.sock")) if directory.is_dir() else []
    if len(found) != 1:
        raise ControlError(
            f"expected one control socket in {directory}, found {len(found)}; pass --control PATH"
        )
    return found[0]


def render_pending(answer: JsonObject) -> str:
    """The `pending` answer as text for the user's terminal (control characters made visible)."""
    cards = answer.get("pending")
    if not isinstance(cards, list) or not cards:
        return "no escalation is waiting"
    blocks: list[str] = []
    for card in cards:
        item = as_object(card)
        if item is None:
            continue
        head = (
            f"{item.get('endorsement_id')}: {item.get('tool')} (call {item.get('call_id')}), "
            f"{item.get('remaining_approvals')} approval(s) left"
        )
        text = as_str(item.get("card_text")) or ""
        blocks.append(printable(head + "\n" + "\n".join(f"  {row}" for row in text.split("\n"))))
    return "\n".join(blocks)
