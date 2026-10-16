"""Gateway stubs."""

from collections.abc import Sequence

from notary_core.models import NotaryModel, Sha256Hex, ValueRef


class ToolPin(NotaryModel):
    """Pins a tool to the hash of its description so later rewrites are detected."""

    tool: str
    description_hash: Sha256Hex


class Gateway:
    """Sits between an agent and MCP servers. Not implemented yet."""

    def __init__(self, pins: Sequence[ToolPin]) -> None:
        self.pins = tuple(pins)

    def check_pins(self, tool: str, description_hash: str) -> bool:
        """Return True iff the tool's current description matches its pin."""
        raise NotImplementedError

    def label_result(self, tool: str, raw: str) -> ValueRef:
        """Wrap a raw tool result into a labeled `ValueRef`."""
        raise NotImplementedError
