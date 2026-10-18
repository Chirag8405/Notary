"""The proxy's config file: which server(s) to front and the user's contract for this session.

One contract covers every server: `server` (one server, named `default`) or `servers` (name ->
spec, each tool names its `server`). Tool names stay the servers' own names; a clash is resolved
with `remote_name`, never by an automatic prefix, so reviewed policy rows keep applying.

The config stands in for the Intent Compiler: the user writes the contract by hand. Manifest
hashes are not written; they are pinned from what the server reports at startup.
"""

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

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
from notary_mcp_proxy.structured import StructureError, validate_pattern

PUBLIC: tuple[str, ...] = ("*",)
DEFAULT_SERVER = "default"
"""Name of the one server of the single `server` form."""


class ServerSpec(NotaryModel):
    command: Annotated[tuple[str, ...], Field(min_length=1)]
    """Run in the config file's directory."""
    timeout_seconds: Annotated[float, Field(gt=0)] = 30.0
    """How long one request to the server may take before the call is answered with an error."""


class ParamSpec(NotaryModel):
    marker: Marker
    unit: DecisionUnit | None = None
    kind: ParamKind = "other"
    """`unit` and `kind` are ignored for a tool `DEFAULT_POLICY` knows: the reviewed row wins."""


class FieldSpec(NotaryModel):
    """Config for one field of a tool's `structuredContent`; unset keys fall back to the tool."""

    readers: tuple[str, ...] | None = None
    """Who may read the field; none means the tool's readers."""
    unit: DecisionUnit | None = None
    """How the resolver compares a quote of the field (e.g. `iban` ignores spaces and case)."""


class ToolSpec(NotaryModel):
    effect: ToolEffect
    server: str | None = None
    """Which server runs the tool; required with several servers, else the only one."""
    remote_name: str | None = None
    """The server's name for the tool when the contract name differs. Reviewed policy rows and
    the pinned manifest use the contract name; the parameters must be classified under it."""
    params: dict[str, ParamSpec] = {}
    readers: tuple[str, ...] = PUBLIC
    """Who may read this tool's results; `["user"]` marks them secret."""
    origin: Origin | None = None
    """Origin of the results; none means `tool:<name>`. Results are always untrusted."""
    fields: dict[str, FieldSpec] = {}
    """Per-field config of `structuredContent`, keyed by path (`iban`, `items.*.iban`; see
    `structured.py`). It applies only to paths the tool's pinned `outputSchema` declares; any
    other key the server sends gets the tool's readers and no unit. A pattern covers the paths
    below it too, and the most specific pattern that sets a value wins."""

    @field_validator("fields")
    @classmethod
    def _patterns_are_paths(cls, fields: dict[str, FieldSpec]) -> dict[str, FieldSpec]:
        for pattern, spec in fields.items():
            try:
                validate_pattern(pattern)
            except StructureError as failure:
                raise ValueError(f"field pattern {pattern!r}: {failure}") from failure
            if spec.readers is None and spec.unit is None:
                raise ValueError(f"field pattern {pattern!r} sets neither readers nor unit")
        return fields


class LedgerSpec(NotaryModel):
    """A user-authored ledger entry, e.g. a known payee."""

    ledger: str
    key: str
    unit: DecisionUnit
    value: str


class ProxyConfig(NotaryModel):
    single_server: ServerSpec | None = Field(default=None, alias="server")
    """The single form, `"server": {...}`: one server, named `default`."""
    named_servers: dict[str, ServerSpec] = Field(default_factory=dict, alias="servers")
    """The several-servers form, `"servers": {name: {...}}`. Give exactly one of the two."""
    user_intent: str
    tools: dict[str, ToolSpec]
    budget: EffectBudget
    egress_hosts: tuple[str, ...] = ()
    authorized_irreversible: tuple[str, ...] = ()
    ledger: tuple[LedgerSpec, ...] = ()

    @model_validator(mode="after")
    def _routes_are_valid(self) -> Self:
        if (self.single_server is None) == (not self.named_servers):
            raise ValueError("give exactly one of `server` and `servers`")
        seen: dict[tuple[str, str], str] = {}
        for tool, spec in sorted(self.tools.items()):
            name = spec.server
            if name is None:
                if len(self.servers) != 1:
                    raise ValueError(f"tool {tool!r}: `server` is required with several servers")
                name = next(iter(self.servers))
            if name not in self.servers:
                raise ValueError(f"tool {tool!r}: unknown server {name!r}")
            route = (name, spec.remote_name or tool)
            if route in seen:
                raise ValueError(
                    f"tools {seen[route]!r} and {tool!r} are both {route[1]!r} on server {name!r}"
                )
            seen[route] = tool
        return self

    @property
    def servers(self) -> dict[str, ServerSpec]:
        """Name -> spec for either form."""
        if self.single_server is not None:
            return {DEFAULT_SERVER: self.single_server}
        return dict(self.named_servers)

    @property
    def server(self) -> ServerSpec:
        """The only server (the single form); an error when there are several."""
        if len(self.servers) != 1:
            raise ValueError("the config has several servers; use `servers`")
        return next(iter(self.servers.values()))

    @property
    def multi(self) -> bool:
        return len(self.servers) > 1


def routes(config: ProxyConfig) -> Mapping[str, tuple[str, str]]:
    """Contract tool name -> (server name, the server's name for the tool)."""
    only = next(iter(config.servers))
    return {
        tool: (spec.server or only, spec.remote_name or tool) for tool, spec in config.tools.items()
    }


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


def tool_fields(config: ProxyConfig) -> Mapping[str, Mapping[str, FieldSpec]]:
    return {tool: spec.fields for tool, spec in config.tools.items() if spec.fields}
