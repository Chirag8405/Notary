"""The proxy's config file: which server(s) to front and the user's contract for this session.

One contract covers every server: `server` (one server, named `default`) or `servers` (name ->
spec, each tool names its `server`). Tool names stay the servers' own names; a clash is resolved
with `remote_name`, never by an automatic prefix, so reviewed policy rows keep applying.

The config stands in for the Intent Compiler: the user writes the contract by hand. Manifest
hashes are not written; they are pinned from what the server reports at startup.
"""

import re
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    ConfigDict,
    Discriminator,
    Field,
    JsonValue,
    Tag,
    field_validator,
    model_validator,
)

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
from notary_mcp_proxy.hosts import is_loopback_host
from notary_mcp_proxy.structured import StructureError, validate_pattern

PUBLIC: tuple[str, ...] = ("*",)
RecordReaders = Literal["config", "narrow_by_server"]
DEFAULT_SERVER = "default"
"""Name of the one server of the single `server` form."""
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[^\s]*")
"""A URI prefix starts with a scheme and holds no whitespace."""
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_CREDENTIAL_HEADER = re.compile(r"authorization|cookie|token|key|secret|password|credential")
MANAGED_HEADERS = frozenset(
    {
        "accept",
        "connection",
        "content-length",
        "content-type",
        "host",
        "mcp-protocol-version",
        "mcp-session-id",
        "transfer-encoding",
    }
)
"""Headers the HTTP client sets itself; a config may not."""
RESOURCE_SOURCE = "resource:"
PROMPT_SOURCE = "prompt:"
"""Prefixes of the synthetic labeling sources `resource:<server>` / `prompt:<server>`: the tool name
the labeler sees for content that is not a tool result. No contract tool may use them."""


class ConfigModel(NotaryModel):
    """Base of the config models: a field's docstring becomes its JSON Schema `description`, so an
    editor shows it (the schema is `schema/proxy-config.schema.json`)."""

    model_config = ConfigDict(use_attribute_docstrings=True)


def resource_source(server: str) -> str:
    return f"{RESOURCE_SOURCE}{server}"


def prompt_source(server: str) -> str:
    return f"{PROMPT_SOURCE}{server}"


class ResourcePolicy(ConfigModel):
    """Which resources of one server the agent may see and read; the rest stays hidden."""

    allow: Annotated[tuple[str, ...], Field(min_length=1)]
    """URI prefixes, e.g. `file:///docs/` (end a directory with `/`: the match is a plain string
    prefix). A URI outside every prefix is neither listed nor readable, and a read of it is
    answered without contacting the server."""
    readers: tuple[str, ...] = PUBLIC
    """Who may read the content; `["user"]` marks it secret."""
    origin: Origin | None = None
    """Origin of the content; none means `tool:resource:<server>`. Content is always untrusted."""

    @field_validator("allow")
    @classmethod
    def _prefixes_are_uris(cls, allow: tuple[str, ...]) -> tuple[str, ...]:
        for prefix in allow:
            if _SCHEME.fullmatch(prefix) is None:
                raise ValueError(f"resource prefix {prefix!r} is not a URI prefix")
        if len(set(allow)) != len(allow):
            raise ValueError("a resource prefix is listed twice")
        return allow


class PromptPolicy(ConfigModel):
    """Which prompts of one server the agent may see and get. Definitions are pinned at startup."""

    allow: Annotated[tuple[str, ...], Field(min_length=1)]
    """Prompt names (exact)."""

    @field_validator("allow")
    @classmethod
    def _names_are_unique(cls, allow: tuple[str, ...]) -> tuple[str, ...]:
        if any(not name for name in allow) or len(set(allow)) != len(allow):
            raise ValueError("prompt names must be non-empty and unique")
        return allow


class _ServerCommon(ConfigModel):
    timeout_seconds: Annotated[float, Field(gt=0)] = 30.0
    """How long one request to the server may take before the call is answered with an error."""
    resources: ResourcePolicy | None = None
    """None (the default): the server's resources are hidden and `resources/*` is not served."""
    prompts: PromptPolicy | None = None
    """None (the default): the server's prompts are hidden and `prompts/*` is not served."""


class StdioServerSpec(_ServerCommon):
    """A server the proxy starts as a child process and speaks to over its stdin and stdout."""

    kind: Literal["stdio"] = "stdio"
    """The only form there was before `kind`: a spec without it is a stdio spec."""
    command: Annotated[tuple[str, ...], Field(min_length=1)]
    """Run in the config file's directory."""


class HttpServerSpec(_ServerCommon):
    """A server reached over MCP Streamable HTTP (spec 2025-06-18) at one endpoint URL."""

    kind: Literal["http"]
    url: str
    """`https://host/path`; plain `http://` only for a loopback host (a bearer token must not
    cross a network in the clear). No user name or password in the URL."""
    headers: dict[str, str] = {}
    """Extra request headers, e.g. `{"Authorization": "Bearer ${GITHUB_TOKEN}"}`. A value may
    reference an environment variable only as `${NAME}`; it is resolved at startup (a missing or
    empty variable fails startup) and never logged. A header that carries a credential
    (`Authorization`, `Cookie`, a name with token / key / secret) must reference a variable: no
    secrets in the config file."""

    @field_validator("url")
    @classmethod
    def _url_is_an_endpoint(cls, url: str) -> str:
        try:
            parts = urlsplit(url)
            host = parts.hostname
            _ = parts.port  # raises ValueError for a bad port
        except ValueError as failure:
            raise ValueError("`url` is not a valid URL") from failure
        if parts.scheme not in ("http", "https") or not host:
            raise ValueError("`url` must be http(s)://host[:port]/path")
        if parts.username is not None or parts.password is not None:
            raise ValueError("`url` must not carry a user name or password; use `headers`")
        if parts.fragment:
            raise ValueError("`url` must not have a fragment")
        if parts.scheme == "http" and not is_loopback_host(host):
            raise ValueError("`url` must be https unless the host is loopback")
        return url

    @field_validator("headers")
    @classmethod
    def _headers_are_safe(cls, headers: dict[str, str]) -> dict[str, str]:
        seen: set[str] = set()
        for name, value in headers.items():
            lowered = name.lower()
            if _HEADER_NAME.fullmatch(name) is None:
                raise ValueError(f"header name {name!r} is not a valid HTTP header name")
            if lowered in seen:
                raise ValueError(f"header {name!r} is listed twice")
            seen.add(lowered)
            if lowered in MANAGED_HEADERS:
                raise ValueError(f"header {name!r} is set by the proxy and cannot be configured")
            references = header_references(name, value)
            if not references and _CREDENTIAL_HEADER.search(lowered):
                raise ValueError(
                    f"header {name!r} carries a credential: write it as ${{NAME}} (an "
                    "environment variable), not as a literal"
                )
            if "\r" in value or "\n" in value:
                raise ValueError(f"header {name!r}: a value may not contain a line break")
        return headers


def header_references(name: str, value: str) -> tuple[str, ...]:
    """The environment variables a header value names, as `${NAME}`; a stray `${` is an error."""
    if "${" in _REFERENCE.sub("", value):
        raise ValueError(f"header {name!r}: write an environment variable as ${{NAME}}")
    return tuple(_REFERENCE.findall(value))


def _server_kind(value: JsonValue | StdioServerSpec | HttpServerSpec) -> str | None:
    """The union tag: a spec without `kind` is the old stdio form."""
    if isinstance(value, dict):
        kind = value.get("kind", "stdio")
        return kind if isinstance(kind, str) else None
    if isinstance(value, (StdioServerSpec, HttpServerSpec)):
        return value.kind
    return None


ServerSpec = Annotated[
    Annotated[StdioServerSpec, Tag("stdio")] | Annotated[HttpServerSpec, Tag("http")],
    Discriminator(_server_kind),
]
"""A server: `{"kind": "stdio", "command": [...]}` or `{"kind": "http", "url": ...}`.
The old form without `kind` (`{"command": [...]}`) still means stdio."""


class ParamSpec(ConfigModel):
    marker: Marker
    unit: DecisionUnit | None = None
    kind: ParamKind = "other"
    """`unit` and `kind` are ignored for a tool `DEFAULT_POLICY` knows: the reviewed row wins."""


class FieldSpec(ConfigModel):
    """Config for one field of a tool's `structuredContent`; unset keys fall back to the tool."""

    readers: tuple[str, ...] | None = None
    """Who may read the field; none means the tool's readers."""
    unit: DecisionUnit | None = None
    """How the resolver compares a quote of the field (e.g. `iban` ignores spaces and case)."""


class ToolSpec(ConfigModel):
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

    records: bool = False
    """The tool's `structuredContent` is `{"records": [{"record_id", "readers", "fields": [{"name",
    "text", "unit"}]}]}`: each record becomes one record of the result with the server's
    `record_id`, so a value id is `<call_id>.<record_id>.<field>` (see `mcp_backend.py`)."""
    record_readers: RecordReaders = "config"
    """Whose readers a record gets. `config`: the tool's `readers`, whatever the server says.
    `narrow_by_server`: the join (intersection) of the tool's `readers` and the record's own,
    so a server can make a record more secret but never more public. Needs `records`."""

    @model_validator(mode="after")
    def _record_settings_fit(self) -> Self:
        if self.record_readers != "config" and not self.records:
            raise ValueError("`record_readers` other than `config` needs `records`")
        if self.records and self.fields:
            raise ValueError("`fields` does not apply to a tool with `records`")
        return self

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


class LedgerSpec(ConfigModel):
    """A user-authored ledger entry, e.g. a known payee."""

    ledger: str
    key: str
    unit: DecisionUnit
    value: str


class ApprovalSettings(ConfigModel):
    elicitation: bool = True
    """Ask the user to approve an escalation in the client's own UI (MCP elicitation) when the
    client declared the capability. The control socket works either way; the first answer wins."""


class ProxyConfig(ConfigModel):
    """The NOTARY MCP proxy config: the servers to front and the user's contract for the session."""

    # Exactly one of `server` and `servers`: the validator below enforces it, this tells editors.
    model_config = ConfigDict(
        json_schema_extra={"oneOf": [{"required": ["server"]}, {"required": ["servers"]}]}
    )

    schema_uri: str | None = Field(default=None, alias="$schema")
    """Optional pointer to `proxy-config.schema.json` for editors; the proxy ignores it."""
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
    approvals: ApprovalSettings = ApprovalSettings()

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

    @model_validator(mode="after")
    def _content_is_unambiguous(self) -> Self:
        """A URI or prompt name must belong to exactly one server, and tools may not shadow the
        synthetic sources."""
        for tool in sorted(self.tools):
            if tool.startswith((RESOURCE_SOURCE, PROMPT_SOURCE)):
                raise ValueError(
                    f"tool {tool!r}: names starting with {RESOURCE_SOURCE!r} or "
                    f"{PROMPT_SOURCE!r} are reserved for resources and prompts"
                )
        prefixes: list[tuple[str, str]] = []
        names: dict[str, str] = {}
        for server, spec in sorted(self.servers.items()):
            if spec.resources is not None:
                prefixes.extend((server, prefix) for prefix in spec.resources.allow)
            if spec.prompts is not None:
                for name in spec.prompts.allow:
                    if name in names:
                        raise ValueError(
                            f"prompt {name!r} is allowed on servers {names[name]!r} and {server!r}"
                        )
                    names[name] = server
        for index, (server, prefix) in enumerate(prefixes):
            for other, longer in prefixes[index + 1 :]:
                if other != server and (longer.startswith(prefix) or prefix.startswith(longer)):
                    raise ValueError(
                        f"resource prefixes {prefix!r} (server {server!r}) and {longer!r} "
                        f"(server {other!r}) overlap"
                    )
        return self

    @property
    def servers(self) -> dict[str, ServerSpec]:
        """Name -> spec for either form."""
        if self.single_server is not None:
            return {DEFAULT_SERVER: self.single_server}
        return dict(self.named_servers)

    @property
    def server(self) -> StdioServerSpec:
        """The only server, which must be a stdio one: an error for several or for an HTTP one."""
        if len(self.servers) != 1:
            raise ValueError("the config has several servers; use `servers`")
        spec = next(iter(self.servers.values()))
        if not isinstance(spec, StdioServerSpec):
            raise ValueError("the server is not a stdio server; it has no command")
        return spec

    @property
    def multi(self) -> bool:
        return len(self.servers) > 1


def resolve_headers(server: str, spec: HttpServerSpec, env: Mapping[str, str]) -> dict[str, str]:
    """The headers to send, each `${NAME}` replaced by the variable in `env`.

    A variable that is missing or empty, or whose value holds a line break, raises `ValueError`
    naming the server, the header and the variable, never the value.
    """
    resolved: dict[str, str] = {}
    for name, template in spec.headers.items():
        value = template
        for variable in header_references(name, template):
            text = env.get(variable)
            if not text:
                raise ValueError(
                    f"server {server!r}: header {name!r} needs the environment variable "
                    f"{variable}, which is not set"
                )
            if any(char in text for char in "\r\n\0"):
                raise ValueError(
                    f"server {server!r}: the environment variable {variable} (header {name!r}) "
                    "contains a line break or a NUL"
                )
            value = value.replace("${" + variable + "}", text)
        resolved[name] = value
    return resolved


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
    origins = [
        ToolOriginRule(tool=tool, origin=spec.origin)
        for tool, spec in sorted(config.tools.items())
        if spec.origin is not None
    ]
    origins.extend(
        ToolOriginRule(tool=resource_source(server), origin=spec.resources.origin)
        for server, spec in sorted(config.servers.items())
        if spec.resources is not None and spec.resources.origin is not None
    )
    return LabelingPolicy(origins=tuple(origins), stamps=())


def tool_readers(config: ProxyConfig) -> Mapping[str, tuple[str, ...]]:
    return {tool: spec.readers for tool, spec in config.tools.items()}


def tool_fields(config: ProxyConfig) -> Mapping[str, Mapping[str, FieldSpec]]:
    return {tool: spec.fields for tool, spec in config.tools.items() if spec.fields}
