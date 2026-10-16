"""The tool backend: the one seam where a real MCP transport plugs in (P6).

The Gateway never talks to a server itself. It is given a `ToolBackend`, asks it for the tool
manifests it reports and, only after an ALLOW decision is logged, calls one tool. This module
holds shapes and one helper; it has no network, file or process code.
"""

import json
from collections.abc import Mapping, Sequence
from typing import Annotated, Protocol

from pydantic import Field

from notary_core.gateway import ToolResultField
from notary_core.models import NotaryModel
from notary_core.pinning import ToolManifest

NonNegInt = Annotated[int, Field(ge=0)]


class BackendRecord(NotaryModel):
    """One record of a tool result, to be split into labeled field values."""

    record_id: str
    readers: tuple[str, ...]
    """Who may read the record: `("*",)` public, `("user",)` a secret."""
    fields: tuple[ToolResultField, ...]


class BackendEffect(NotaryModel):
    """What a call did, as the backend reports it."""

    summary: str
    spent_cents: NonNegInt
    egress_bytes: NonNegInt
    mutating: bool
    """False for a read: the session's effect count is not advanced."""


class BackendResult(NotaryModel):
    records: tuple[BackendRecord, ...]
    effect: BackendEffect | None
    error: str | None


class ToolBackend(Protocol):
    """What the Gateway needs from an MCP server (or a test double)."""

    def list_tools(self) -> Sequence[ToolManifest]:
        """The manifests the server reports now."""
        ...

    def call_tool(self, tool: str, args: Mapping[str, str]) -> BackendResult:
        """Run one tool. Only the Gateway calls this, and only after a logged ALLOW."""
        ...


def schema_text(schema: Mapping[str, object]) -> str:
    """Canonical text of a tool's input schema, for `ToolManifest.input_schema`.

    Sorted keys and compact separators, so key order and whitespace of the source do not matter.
    Floats are kept (core cannot hash them, which is why the schema travels as text).
    """
    return json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
