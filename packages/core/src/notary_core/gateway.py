"""Pure Gateway and Value Store interfaces (frozen contract; implementations arrive in P3a).

Only the shapes live here: the tool-calling I/O adapter belongs in `packages/mcp-proxy`.
"""

from collections.abc import Iterable, Mapping
from typing import Protocol

from notary_core.models import DecisionUnit, Integrity, NotaryModel, Origin, ResolvedValue


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


class FieldStamp(NotaryModel):
    """A field the platform itself stamps (e.g. a verified-sender flag), with its integrity."""

    tool: str
    field: str
    integrity: Integrity


class ToolOriginRule(NotaryModel):
    """The origin of every value a tool returns."""

    tool: str
    origin: Origin


class LabelingPolicy(NotaryModel):
    """Which tools produce which origin and which fields are platform facts.

    Stamps are keyed by (tool, field NAME): the field names must come from the tool's own schema,
    never from content. A tool that echoes attacker-chosen field names must not be given stamps.
    """

    origins: tuple[ToolOriginRule, ...]
    stamps: tuple[FieldStamp, ...]


DEFAULT_LABELING = LabelingPolicy(origins=(), stamps=())
"""Fail closed: every value gets `ToolOrigin(name=tool)` and is untrusted."""


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
