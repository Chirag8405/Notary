"""Policy table machinery: strictness order, floor merging and fail-closed lookups (I2)."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Self

from pydantic import model_validator

from notary_core.models import (
    DecisionUnit,
    EndorseMarker,
    FreeMarker,
    LedgerMarker,
    LiteralMarker,
    Marker,
    NamedSourceMarker,
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


class ParamBinding(NotaryModel):
    name: str
    policy: ParamPolicy


class ToolPolicy(NotaryModel):
    effect: ToolEffect
    params: tuple[ParamBinding, ...]
    """Immutable by construction (a strict `dict` cannot be frozen); use `make_tool_policy`."""

    @model_validator(mode="after")
    def _names_are_unique(self) -> Self:
        names = [binding.name for binding in self.params]
        if len(names) != len(set(names)):
            raise ValueError("a tool policy cannot bind the same parameter twice")
        return self


def make_tool_policy(effect: ToolEffect, params: Mapping[str, ParamPolicy]) -> ToolPolicy:
    """Build a `ToolPolicy`, sorting bindings by name so insertion order never shows."""
    bindings = tuple(ParamBinding(name=name, policy=params[name]) for name in sorted(params))
    return ToolPolicy(effect=effect, params=bindings)


PolicyTable = Mapping[str, ToolPolicy]
"""Tool name -> policy."""

_ENDORSE = EndorseMarker(kind="endorse")
_FREE = FreeMarker(kind="free")


def _ledger(name: str) -> LedgerMarker:
    return LedgerMarker(kind="ledger", ledger=name)


def _destination(unit: DecisionUnit, ledger: str) -> ParamPolicy:
    return ParamPolicy(unit=unit, floor=_ledger(ledger), kind="destination")


_PAYLOAD = ParamPolicy(unit=None, floor=_FREE, kind="payload")
_FREE_IDENTIFIER = ParamPolicy(unit="identifier", floor=_FREE, kind="identifier")
_ENDORSED_IDENTIFIER_PARAMS: Mapping[str, DecisionUnit] = {
    "name": "identifier",
    "iban": "iban",
    "email": "email",
}
_PAYMENT = {
    "payee": _destination("iban", "payees"),
    "amount": ParamPolicy(unit="amount", floor=_FREE, kind="amount"),
    "reference": _PAYLOAD,
}

_DEFAULT_ENTRIES: dict[str, ToolPolicy] = {
    "read_email": make_tool_policy("read", {"message_id": _FREE_IDENTIFIER}),
    "list_files": make_tool_policy("read", {"path": _FREE_IDENTIFIER}),
    "read_file": make_tool_policy("read", {"path": _FREE_IDENTIFIER}),
    # `send_money` and `pay_bill` are both listed: the scaffold sample uses `pay_bill`, the planned
    # world tools use `send_money`; lane B owns tool names and may delete one.
    "send_money": make_tool_policy("irreversible", _PAYMENT),
    "pay_bill": make_tool_policy("irreversible", _PAYMENT),
    "send_email": make_tool_policy(
        "write",
        {
            "to": _destination("email", "contacts"),
            "cc": _destination("email", "contacts"),
            "subject": _PAYLOAD,
            "body": _PAYLOAD,
        },
    ),
    "post_slack": make_tool_policy(
        "write", {"channel": _destination("identifier", "channels"), "text": _PAYLOAD}
    ),
    "create_event": make_tool_policy(
        "write",
        {
            "attendees": _destination("email", "contacts"),
            "title": _PAYLOAD,
            "description": _PAYLOAD,
        },
    ),
    "delete_email": make_tool_policy(
        "irreversible",
        {"message_id": ParamPolicy(unit="identifier", floor=_ENDORSE, kind="identifier")},
    ),
    "add_contact": make_tool_policy(
        "write",
        {
            name: ParamPolicy(unit=unit, floor=_ENDORSE, kind="identifier")
            for name, unit in _ENDORSED_IDENTIFIER_PARAMS.items()
        },
    ),
}
DEFAULT_POLICY: PolicyTable = MappingProxyType(_DEFAULT_ENTRIES)
"""Read-only at the top level; every tool's params are immutable by construction. Reviewed as
Markdown (`scripts/print_sensitive_params.py`); `assert_covered` guards it against new params."""

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
    for binding in tool_policy.params:
        if binding.name == param:
            return binding.policy
    return UNKNOWN_PARAM


def effective_effect(policy: PolicyTable, tool: str, declared: ToolEffect | None) -> ToolEffect:
    tool_policy = policy.get(tool)
    table_effect = UNKNOWN_TOOL_EFFECT if tool_policy is None else tool_policy.effect
    return table_effect if declared is None else stricter_effect(table_effect, declared)


def effective_marker(policy: PolicyTable, tool: str, param: str, proposed: Marker | None) -> Marker:
    return merge_with_compiler_markers(param_policy(policy, tool, param).floor, proposed)


@dataclass(frozen=True, slots=True)
class ManifestInfo:
    """What the policy needs from a tool manifest (keeps core independent of `notary_world`)."""

    tool: str
    effect: ToolEffect
    params: tuple[str, ...]


class PolicyCoverageError(Exception):
    def __init__(self, missing: tuple[tuple[str, str], ...]) -> None:
        self.missing = missing
        listing = ", ".join(f"{tool}.{param}" for tool, param in missing)
        super().__init__(f"unclassified parameters of effect tools: {listing}")


def unclassified_params(
    policy: PolicyTable, manifests: Sequence[ManifestInfo]
) -> tuple[tuple[str, str], ...]:
    """Sorted `(tool, param)` pairs of non-read tools that the table does not classify.

    The stricter of manifest and table effect decides, so a tool missing from the table counts as
    irreversible (all its params are listed) even if its manifest says `read`.
    """
    missing: set[tuple[str, str]] = set()
    for manifest in manifests:
        if effective_effect(policy, manifest.tool, manifest.effect) == "read":
            continue
        tool_policy = policy.get(manifest.tool)
        bound = (
            frozenset[str]()
            if tool_policy is None
            else frozenset(binding.name for binding in tool_policy.params)
        )
        missing.update((manifest.tool, param) for param in manifest.params if param not in bound)
    return tuple(sorted(missing))


def assert_covered(policy: PolicyTable, manifests: Sequence[ManifestInfo]) -> None:
    missing = unclassified_params(policy, manifests)
    if missing:
        raise PolicyCoverageError(missing)


def _floor_label(marker: Marker) -> str:
    if isinstance(marker, LedgerMarker):
        return f"ledger({marker.ledger})"
    if isinstance(marker, NamedSourceMarker):
        return f"named_source({marker.source})"
    if isinstance(marker, LiteralMarker):
        return f"literal({marker.value!r})"
    return marker.kind


def render_markdown(policy: PolicyTable) -> str:
    """The table as Markdown for review, sorted by tool then param (no dict-order dependence)."""
    lines = [
        "| Tool | Effect | Param | Unit | Floor | Kind |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for tool in sorted(policy):
        tool_policy = policy[tool]
        for binding in sorted(tool_policy.params, key=lambda b: b.name):
            param = binding.policy
            cells = (
                tool,
                tool_policy.effect,
                binding.name,
                str(param.unit),
                _floor_label(param.floor),
                param.kind,
            )
            lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"
