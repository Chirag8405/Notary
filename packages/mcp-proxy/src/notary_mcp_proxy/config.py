"""The proxy's config file: which server to front and the user's contract for this session.

The config stands in for the Intent Compiler: the user writes the contract by hand. Manifest
hashes are not written; they are pinned from what the server reports at startup.
"""

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Annotated

from pydantic import Field

from notary_core.canon import sha256_hex
from notary_core.gateway import LabelingPolicy, ToolOriginRule
from notary_core.models import (
    DecisionUnit,
    EffectBudget,
    FreeMarker,
    IntentContract,
    Label,
    LedgerEntry,
    Marker,
    NotaryModel,
    Origin,
    ToolEffect,
    ToolScope,
    UserAuthoredSource,
    UserOrigin,
    ValueRef,
)
from notary_core.pinning import ToolManifest, manifest_hash
from notary_core.policy.sensitive_params import (
    DEFAULT_POLICY,
    ParamKind,
    ParamPolicy,
    PolicyTable,
    make_tool_policy,
)
from notary_core.units import canonicalize

PUBLIC: tuple[str, ...] = ("*",)


class ServerSpec(NotaryModel):
    command: Annotated[tuple[str, ...], Field(min_length=1)]
    """Run in the config file's directory."""


class ParamSpec(NotaryModel):
    marker: Marker
    unit: DecisionUnit | None = None
    kind: ParamKind = "other"
    """`unit` and `kind` are ignored for a tool `DEFAULT_POLICY` knows: the reviewed row wins."""


class ToolSpec(NotaryModel):
    effect: ToolEffect
    params: dict[str, ParamSpec] = {}
    readers: tuple[str, ...] = PUBLIC
    """Who may read this tool's results; `["user"]` marks them secret."""
    origin: Origin | None = None
    """Origin of the results; none means `tool:<name>`. Results are always untrusted."""


class LedgerSpec(NotaryModel):
    """A user-authored ledger entry, e.g. a known payee."""

    ledger: str
    key: str
    unit: DecisionUnit
    value: str


class ProxyConfig(NotaryModel):
    server: ServerSpec
    user_intent: str
    tools: dict[str, ToolSpec]
    budget: EffectBudget
    egress_hosts: tuple[str, ...] = ()
    authorized_irreversible: tuple[str, ...] = ()
    ledger: tuple[LedgerSpec, ...] = ()


def build_policy(config: ProxyConfig) -> PolicyTable:
    """`DEFAULT_POLICY` plus a row for every config tool it does not know.

    The config is part of the trusted base, so its rows take the contract marker as the contract
    and leave the floor free; a tool the reviewed table knows keeps its row, so a config cannot
    loosen it.
    """
    free = FreeMarker(kind="free")
    rows = dict(DEFAULT_POLICY)
    for tool, spec in config.tools.items():
        if tool in rows:
            continue
        params = {
            name: ParamPolicy(unit=param.unit, floor=free, kind=param.kind)
            for name, param in spec.params.items()
        }
        rows[tool] = make_tool_policy(spec.effect, params)
    return MappingProxyType(rows)


def build_contract(config: ProxyConfig, pinned: Sequence[ToolManifest]) -> IntentContract:
    """The contract with each tool pinned to the hash the server reported at startup."""
    manifests = {manifest.name: manifest for manifest in pinned}
    missing = sorted(tool for tool in config.tools if tool not in manifests)
    if missing:
        raise ValueError(f"the server does not report: {', '.join(missing)}")
    scopes = tuple(
        ToolScope(
            tool=tool,
            params={name: param.marker for name, param in spec.params.items()},
            manifest_hash=manifest_hash(manifests[tool]),
            effect=spec.effect,
        )
        for tool, spec in sorted(config.tools.items())
    )
    return IntentContract(
        contract_id="mcp-proxy",
        user_intent=config.user_intent,
        allowed_tools=scopes,
        budget=config.budget,
        egress_hosts=config.egress_hosts,
        authorized_irreversible=config.authorized_irreversible,
    )


def build_ledger(config: ProxyConfig) -> tuple[LedgerEntry, ...]:
    label = Label(
        origin=UserOrigin(kind="user"), integrity="trusted", readers=PUBLIC, span_pointer=None
    )
    entries: list[LedgerEntry] = []
    for index, spec in enumerate(config.ledger):
        canonical = canonicalize(spec.unit, spec.value).value
        entry_id = f"config-{index}"
        ref = ValueRef(id=f"ledger.{entry_id}", label=label, content_hash=sha256_hex(canonical))
        entries.append(
            LedgerEntry(
                entry_id=entry_id,
                ledger=spec.ledger,
                key=spec.key,
                value=ref,
                unit=spec.unit,
                canonical=canonical,
                source=UserAuthoredSource(kind="user_authored"),
            )
        )
    return tuple(entries)


def build_labeling(config: ProxyConfig) -> LabelingPolicy:
    origins = tuple(
        ToolOriginRule(tool=tool, origin=spec.origin)
        for tool, spec in sorted(config.tools.items())
        if spec.origin is not None
    )
    return LabelingPolicy(origins=origins, stamps=())


def tool_readers(config: ProxyConfig) -> Mapping[str, tuple[str, ...]]:
    return {tool: spec.readers for tool, spec in config.tools.items()}
