"""Pure Gateway and Value Store interfaces (frozen contract; implementations arrive in P3a).

Only the shapes live here: the tool-calling I/O adapter belongs in `packages/mcp-proxy`.
"""

from collections.abc import Iterable, Mapping
from typing import Protocol

from notary_core.canon import sha256_hex
from notary_core.models import (
    DecisionUnit,
    Integrity,
    Label,
    NotaryModel,
    Origin,
    ResolvedValue,
    ToolOrigin,
    ValueRef,
)
from notary_core.provenance import normalize_readers


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


def make_labeler(policy: LabelingPolicy) -> GatewayLabeler:
    """A labeler for `policy`; the policy is validated here, so a bad one fails at construction.

    Labels come only from the tool name, the field name and the caller's readers, never from the
    field text, which is hashed and copied byte-for-byte. Names match exactly (case-sensitive).
    """
    origins: dict[str, Origin] = {}
    for rule in policy.origins:
        if rule.tool in origins:
            raise ValueError(f"duplicate labeling rule: origin for {rule.tool}")
        origins[rule.tool] = rule.origin
    stamps: dict[tuple[str, str], Integrity] = {}
    for stamp in policy.stamps:
        key = (stamp.tool, stamp.field)
        if key in stamps:
            raise ValueError(f"duplicate labeling rule: stamp for {stamp.tool}.{stamp.field}")
        stamps[key] = stamp.integrity

    def labeler(result: ToolResult, *, readers: tuple[str, ...]) -> tuple[ResolvedValue, ...]:
        names = [field.name for field in result.fields]
        for name in names:
            if names.count(name) > 1:
                raise ValueError(f"duplicate field name: {name}")
        origin = origins.get(result.tool, ToolOrigin(kind="tool", name=result.tool))
        shared = normalize_readers(readers)
        values: list[ResolvedValue] = []
        for field in result.fields:
            label = Label(
                origin=origin,
                integrity=stamps.get((result.tool, field.name), "untrusted"),
                readers=shared,
                span_pointer=None,
            )
            # Value ids are unique only within one result; unique record ids are the caller's job.
            ref = ValueRef(
                id=f"{result.record_id}.{field.name}",
                label=label,
                content_hash=sha256_hex(field.text),
            )
            values.append(ResolvedValue(ref=ref, unit=field.unit, text=field.text))
        return tuple(values)

    return labeler


_DEFAULT_LABELER = make_labeler(DEFAULT_LABELING)


def label_tool_result(result: ToolResult, *, readers: tuple[str, ...]) -> tuple[ResolvedValue, ...]:
    """Label a tool result with the fail-closed default policy (a `GatewayLabeler`)."""
    return _DEFAULT_LABELER(result, readers=readers)


class ValueStore(Protocol):
    """Immutable store of labeled values: every update returns a new store."""

    def get(self, value_id: str) -> ResolvedValue | None: ...

    def with_values(self, values: Iterable[ResolvedValue]) -> "ValueStore": ...

    def as_mapping(self) -> Mapping[str, ResolvedValue]:
        """Keyed by `ValueRef.id`; this is what `decide()` receives as `values`."""
        ...
