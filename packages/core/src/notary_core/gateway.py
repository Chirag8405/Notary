"""Pure Gateway and Value Store interfaces (frozen contract; implementations arrive in P3a).

Only the shapes live here: the tool-calling I/O adapter belongs in `packages/mcp-proxy`.
"""

from collections.abc import Iterable, Mapping
from typing import Protocol

from notary_core.models import DecisionUnit, NotaryModel, ResolvedValue


class ToolResultField(NotaryModel):
    """One structured field of a tool result, e.g. the `iban` of an invoice record."""

    name: str
    text: str
    unit: DecisionUnit | None


class ToolResult(NotaryModel):
    tool: str
    record_id: str
    fields: tuple[ToolResultField, ...]


class GatewayLabeler(Protocol):
    """Label the fields of a tool result into stored values (origin, integrity, readers, hash)."""

    def __call__(
        self, result: ToolResult, *, readers: tuple[str, ...]
    ) -> tuple[ResolvedValue, ...]: ...


def label_tool_result(result: ToolResult, *, readers: tuple[str, ...]) -> tuple[ResolvedValue, ...]:
    """Real labeling logic. Not implemented yet (P3a)."""
    raise NotImplementedError


class ValueStore(Protocol):
    """Immutable store of labeled values: every update returns a new store."""

    def get(self, value_id: str) -> ResolvedValue | None: ...

    def with_values(self, values: Iterable[ResolvedValue]) -> "ValueStore": ...

    def as_mapping(self) -> Mapping[str, ResolvedValue]:
        """Keyed by `ValueRef.id`; this is what `decide()` receives as `values`."""
        ...
