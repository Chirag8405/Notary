"""Policy table machinery: strictness order, floor merging and fail-closed lookups (I2)."""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal, Self

from pydantic import model_validator

from notary_core.models import (
    DecisionUnit,
    EndorseMarker,
    LedgerMarker,
    LiteralMarker,
    Marker,
    NotaryModel,
    ToolEffect,
)

MarkerKind = Literal["literal", "named_source", "ledger", "endorse", "free"]
MARKER_STRICTNESS: tuple[MarkerKind, ...] = ("literal", "named_source", "ledger", "endorse", "free")
"""Strictest first."""
EFFECT_STRICTNESS: tuple[ToolEffect, ...] = ("irreversible", "write", "read")
"""Strictest first."""
ParamKind = Literal["destination", "payload", "amount", "identifier", "other"]


class ParamPolicy(NotaryModel):
    unit: DecisionUnit | None
    """`None` = free text."""
    floor: Marker
    """Strictest allowed relaxation. Never a `LiteralMarker` (it needs a value) and never a
    `LedgerMarker` with an empty ledger name (the table must always name the ledger)."""
    kind: ParamKind

    @model_validator(mode="after")
    def _floor_is_valid(self) -> Self:
        if isinstance(self.floor, LiteralMarker):
            raise ValueError("a policy floor cannot be a literal marker: it has no value")
        if isinstance(self.floor, LedgerMarker) and not self.floor.ledger:
            raise ValueError("a ledger floor must name its ledger")
        return self


class ToolPolicy(NotaryModel):
    effect: ToolEffect
    params: dict[str, ParamPolicy]


PolicyTable = Mapping[str, ToolPolicy]
"""Tool name -> policy."""
DEFAULT_POLICY: PolicyTable = MappingProxyType({})
"""Read-only; filled by the data issue."""

UNKNOWN_PARAM = ParamPolicy(unit="identifier", floor=EndorseMarker(kind="endorse"), kind="other")
UNKNOWN_TOOL_EFFECT: ToolEffect = "irreversible"


def marker_rank(marker: Marker) -> int:
    """Index in `MARKER_STRICTNESS` (lower = stricter)."""
    return MARKER_STRICTNESS.index(marker.kind)


def merge_with_compiler_markers(floor: Marker, proposed: Marker | None) -> Marker:
    """Combine a table floor with the compiler's marker; the result is never looser than the floor.

    At equal rank the content decides per kind: a `named_source` is the compiler's (it carries the
    user-named source the floor cannot know), a `ledger` is the floor's (the reviewed table decides
    which ledger authorizes a parameter), `endorse` and `free` carry no content.
    """
    if proposed is None:
        return floor
    floor_rank = marker_rank(floor)
    proposed_rank = marker_rank(proposed)
    if floor_rank < proposed_rank:
        return floor
    if floor_rank > proposed_rank:
        return proposed
    if isinstance(floor, LedgerMarker | LiteralMarker):
        return floor
    return proposed


def stricter_effect(a: ToolEffect, b: ToolEffect) -> ToolEffect:
    return a if EFFECT_STRICTNESS.index(a) <= EFFECT_STRICTNESS.index(b) else b


def param_policy(policy: PolicyTable, tool: str, param: str) -> ParamPolicy:
    tool_policy = policy.get(tool)
    if tool_policy is None:
        return UNKNOWN_PARAM
    return tool_policy.params.get(param, UNKNOWN_PARAM)


def effective_effect(policy: PolicyTable, tool: str, declared: ToolEffect | None) -> ToolEffect:
    tool_policy = policy.get(tool)
    table_effect = UNKNOWN_TOOL_EFFECT if tool_policy is None else tool_policy.effect
    return table_effect if declared is None else stricter_effect(table_effect, declared)


def effective_marker(policy: PolicyTable, tool: str, param: str, proposed: Marker | None) -> Marker:
    return merge_with_compiler_markers(param_policy(policy, tool, param).floor, proposed)
