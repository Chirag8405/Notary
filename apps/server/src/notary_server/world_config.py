"""The proxy config that stands in for a scenario's frozen contract.

`proxy_config_for(scenario, command=...)` writes down, as a `ProxyConfig`, what the engine already
has for the scenario: the contract's tools and markers, units and kinds from `world_policy`, the
origin each tool's results get from `world_labeling_policy`, the user-authored ledger, the budget,
the egress hosts and the authorized irreversible tools. Nothing is added or loosened. The manifest
hashes are not in a config: the proxy pins what the world MCP server reports.

Every result is in the `records` shape with `record_readers = "narrow_by_server"`: a record's
readers come from the world (a secret file is `("user",)`), and the proxy only ever narrows the
tool's readers (public) with them.

Two things of the engine have no config field, so a scenario that needs them is refused:
a non-fresh session (the proxy starts every session at zero) and a ledger entry that is not
user-authored (only the user's own entries can be written into a config).
"""

from collections.abc import Sequence

from notary_core.models import SessionState, UserAuthoredSource
from notary_core.policy.sensitive_params import param_policy
from notary_mcp_proxy.config import (
    PUBLIC,
    ApprovalSettings,
    LedgerSpec,
    ParamSpec,
    ProxyConfig,
    StdioServerSpec,
    ToolSpec,
)
from notary_world.labeling import world_labeling_policy
from notary_world.scenarios import Scenario
from notary_world.tools import world_policy

FRESH_SESSION = SessionState(
    spent_cents=0, effects_used=0, egress_bytes_used=0, approvals_used=0, escalations_used=0
)


def proxy_config_for(scenario: Scenario, *, command: Sequence[str]) -> ProxyConfig:
    """The config of `scenario`; `command` starts the world MCP server serving its world."""
    if scenario.session != FRESH_SESSION:
        raise ValueError("a proxy config cannot start from a session that has spent anything")
    policy = world_policy()
    origins = {rule.tool: rule.origin for rule in world_labeling_policy().origins}
    contract = scenario.contract
    tools = {
        scope.tool: ToolSpec(
            effect=scope.effect,
            params={
                name: ParamSpec(
                    marker=marker,
                    unit=param_policy(policy, scope.tool, name).unit,
                    kind=param_policy(policy, scope.tool, name).kind,
                )
                for name, marker in scope.params.items()
            },
            readers=PUBLIC,
            origin=origins.get(scope.tool),
            records=True,
            record_readers="narrow_by_server",
        )
        for scope in contract.allowed_tools
    }
    ledger: list[LedgerSpec] = []
    for entry in scenario.ledger:
        if not isinstance(entry.source, UserAuthoredSource):
            raise ValueError(f"ledger entry {entry.entry_id} is not user-authored")
        ledger.append(
            LedgerSpec(ledger=entry.ledger, key=entry.key, unit=entry.unit, value=entry.canonical)
        )
    return ProxyConfig(
        server=StdioServerSpec(command=tuple(command)),
        user_intent=contract.user_intent,
        tools=tools,
        budget=contract.budget,
        egress_hosts=contract.egress_hosts,
        authorized_irreversible=contract.authorized_irreversible,
        ledger=tuple(ledger),
        # The X-ray card is the user's own screen and cannot show a code yet (docs/threat-model.md).
        approvals=ApprovalSettings(require_code=False),
    )
