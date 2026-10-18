"""One `ToolBackend` over several MCP servers: one contract, one Value Store, one audit chain.

Each contract tool belongs to one server (`routes`: contract name -> (server, the server's name)).
The Gateway sees the contract names only, so a manifest, a policy row and a label are keyed the
same way whatever server a tool lives on. That is what lets a value read from one server and sent
through another carry its origin and readers across: the monitor judges the flow.

A dead server affects only its own tools (`unavailable_for`); its last listing stays in the
merged one, so the other servers' calls are still pre-flighted and the pins show no drift.
"""

from collections.abc import Mapping
from types import MappingProxyType

from notary_core.models import ToolEffect
from notary_core.pinning import ToolManifest
from notary_core.policy.sensitive_params import PolicyTable
from notary_mcp_proxy.backend import BackendResult
from notary_mcp_proxy.client import StdioClient
from notary_mcp_proxy.config import FieldSpec, ProxyConfig
from notary_mcp_proxy.config import routes as config_routes
from notary_mcp_proxy.mcp_backend import ERR_EXITED, McpBackend, PinnedTool

ERR_UNROUTED = "no tool server is configured for this tool"


class RoutingError(ValueError):
    """The servers and the config do not fit together (startup fails)."""


class RoutingBackend:
    def __init__(
        self, backends: Mapping[str, McpBackend], routes: Mapping[str, tuple[str, str]]
    ) -> None:
        """`routes`: contract tool name -> (server name, the server's name for the tool)."""
        self._backends = dict(backends)
        self._routes = dict(routes)
        for tool, (server, _) in self._routes.items():
            if server not in self._backends:
                raise RoutingError(f"tool {tool!r}: unknown server {server!r}")
        self._by_remote = {route: tool for tool, route in self._routes.items()}
        if len(self._by_remote) != len(self._routes):
            raise RoutingError("two tools route to the same server tool")
        self._last: dict[str, tuple[ToolManifest, ...]] = {}
        self._reported: dict[str, frozenset[str]] = {}

    def list_tools(self) -> tuple[ToolManifest, ...]:
        """One manifest per contract tool (named by the CONTRACT name), then the tools no
        contract tool covers, under the server's own name, when that name is still free.

        A server that is gone contributes its last listing; a server that is alive but fails
        to list raises (the call is not pre-flighted, so it does not run).
        """
        merged: list[ToolManifest] = []
        taken = set(self._routes)
        for server, backend in self._backends.items():
            if backend.unavailable() is None:
                listing = backend.list_tools()
                self._last[server] = listing
            else:
                listing = self._last.get(server, ())
            self._reported[server] = frozenset(manifest.name for manifest in listing)
            for manifest in listing:
                contract = self._by_remote.get((server, manifest.name))
                if contract is not None:
                    merged.append(manifest.model_copy(update={"name": contract}))
                elif manifest.name not in taken:
                    taken.add(manifest.name)
                    merged.append(manifest)
        return tuple(merged)

    def collisions(self) -> tuple[str, ...]:
        """Contract names another server tool also answers to, once every server was listed.

        A tool a server reports under the contract name of another tool is ambiguous: the
        contract's reviewed row would apply to the wrong tool. A server tool that the config
        covers under another contract name (`remote_name`) is not a collision.
        """
        found: list[str] = []
        for tool, own in sorted(self._routes.items()):
            for server in self._backends:
                if (server, tool) == own or (server, tool) in self._by_remote:
                    continue
                if tool in self._reported.get(server, frozenset()):
                    found.append(
                        f"tool {tool!r} (server {own[0]!r}) is also reported by server "
                        f"{server!r}; give one of them a `remote_name` and a different name"
                    )
        return tuple(found)

    def pinned_definitions(self) -> tuple[PinnedTool, ...]:
        """The first-listed definitions of the contract tools, named by the contract name."""
        out: list[PinnedTool] = []
        for server, backend in self._backends.items():
            for tool in backend.pinned_definitions():
                contract = self._by_remote.get((server, tool.name))
                if contract is not None:
                    out.append(tool.model_copy(update={"name": contract}))
        return tuple(out)

    def unavailable_for(self, tool: str) -> str | None:
        """The error text when the server that owns `tool` is gone; None for an unknown tool."""
        route = self._routes.get(tool)
        if route is None:
            return None
        return self._backends[route[0]].unavailable()

    def unavailable(self) -> str | None:
        """Only when every server is gone."""
        if all(backend.unavailable() is not None for backend in self._backends.values()):
            return ERR_EXITED
        return None

    def call_tool(self, tool: str, args: Mapping[str, str]) -> BackendResult:
        route = self._routes.get(tool)
        if route is None:
            return BackendResult(records=(), effect=None, error=ERR_UNROUTED)
        server, remote = route
        return self._backends[server].call_tool(remote, args)


def build_routing(
    config: ProxyConfig,
    clients: Mapping[str, StdioClient],
    *,
    policy: PolicyTable,
    readers: Mapping[str, tuple[str, ...]],
    fields: Mapping[str, Mapping[str, FieldSpec]],
) -> RoutingBackend:
    """A `McpBackend` per server, keyed by the server's own tool names, behind one router.

    A server's backend looks up a tool's row, effect, readers and field config by the name the
    server uses, so each is re-keyed from the contract name; a tool without `remote_name` is
    unchanged.
    """
    mapping = config_routes(config)
    effects: Mapping[str, ToolEffect] = {tool: spec.effect for tool, spec in config.tools.items()}
    backends: dict[str, McpBackend] = {}
    for server in config.servers:
        client = clients[server]
        own = {tool: remote for tool, (name, remote) in mapping.items() if name == server}
        view = {
            **policy,
            **{remote: policy[tool] for tool, remote in own.items() if tool in policy},
        }
        backends[server] = McpBackend(
            client,
            policy=MappingProxyType(view),
            effects={remote: effects[tool] for tool, remote in own.items()},
            readers={remote: readers[tool] for tool, remote in own.items() if tool in readers},
            fields={remote: fields[tool] for tool, remote in own.items() if tool in fields},
        )
    return RoutingBackend(backends, mapping)
