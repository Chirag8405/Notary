"""Client -> server commands on the run socket: validation, run scoping and routing."""

import contextlib
from collections.abc import Callable
from typing import Literal

from pydantic import ValidationError

from notary_core.models import Command, Lane, NotaryModel
from notary_world.golden import COMMAND_ADAPTER

CLOSE_BAD_REQUEST = 4400
CLOSE_UNKNOWN_SCENARIO = 4404
CLOSE_COMMAND_CONFLICT = 4409
CLOSE_UNSUPPORTED_COMMAND = 4422
CLOSE_MODE_UNAVAILABLE = 4501


class CommandContext(NotaryModel):
    run_id: str | None
    """The run id of the latest event sent on this socket; None before the first event."""
    lane: Lane


class CommandRejected(Exception):  # noqa: N818
    """The command is refused; the socket closes with `code` and `reason`.

    The reason is a fixed phrase and never contains any part of the client's frame.
    """

    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


CommandHandler = Callable[[Command, CommandContext], None]
"""Called on the event loop thread, so it must not block."""


class CommandRouter:
    def __init__(self) -> None:
        self._handlers: dict[str, CommandHandler] = {}

    def register(
        self, command_type: Literal["endorsement_decision"], handler: CommandHandler
    ) -> None:
        self._handlers[command_type] = handler

    def dispatch(self, raw: str, context: CommandContext) -> None:
        command: Command | None = None
        with contextlib.suppress(ValidationError):
            command = COMMAND_ADAPTER.validate_json(raw)
        if command is None:
            # Raised outside the `except` block so the frame text is not kept in an exception chain.
            raise CommandRejected(CLOSE_BAD_REQUEST, "invalid command")
        if context.run_id is None:
            raise CommandRejected(CLOSE_COMMAND_CONFLICT, "run not started")
        if command.type != "endorsement_decision":
            raise CommandRejected(CLOSE_UNSUPPORTED_COMMAND, "command not supported on this socket")
        handler = self._handlers.get(command.type)
        if handler is None:
            raise CommandRejected(CLOSE_UNSUPPORTED_COMMAND, "command not supported on this socket")
        if command.run_id != context.run_id:
            raise CommandRejected(CLOSE_COMMAND_CONFLICT, "command is for another run")
        handler(command, context)
