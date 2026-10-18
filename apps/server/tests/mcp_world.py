"""Run a scenario's scripted calls through the real proxy over a real stdio world server.

`run_through_proxy` starts `python -m notary_server.world_mcp` as a child process (stdio pipes),
fronts it with an in-process `ProxyServer` + `McpBackend` built from `proxy_config_for`, sends each
scripted call as a `tools/call` request, resolves each escalation the way the attack setup says
(the Gateway's approve/reject: the transport for approvals is a separate issue), and reads the
final world back from the server's `--dump-state` file after the server is closed.
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path

from notary_core.models import (
    CallProposed,
    Decision,
    DecisionMade,
    EndorsementRequested,
    LedgerEntry,
    UserEndorsedSource,
)
from notary_mcp_proxy.client import StdioClient
from notary_mcp_proxy.gateway import Gateway
from notary_mcp_proxy.jsonrpc import JsonObject
from notary_mcp_proxy.main import build_server
from notary_mcp_proxy.server import ProxyServer
from notary_server.world_config import proxy_config_for
from notary_world.attacks import attack_world, control_world, get_setup
from notary_world.executor import MAX_ESCALATION_ROUNDS, EscalationMode
from notary_world.models import ScriptedCall
from notary_world.scenarios import Scenario
from notary_world.state import WorldState
from notary_world.tools import RawToolCall, param_unit


@dataclass
class ProxiedCall:
    call_id: str
    scripted: ScriptedCall
    response: JsonObject
    """The `tools/call` result the agent got for the first proposal."""
    decisions: list[Decision] = field(default_factory=list)
    """Every decision of the call in order: the first, then one per approval."""

    @property
    def first(self) -> Decision:
        return self.decisions[0]


@dataclass
class ProxiedRun:
    item_id: str
    scenario: Scenario
    escalation: EscalationMode
    calls: list[ProxiedCall]
    gateway: Gateway
    world_after: WorldState
    engine_calls: tuple[RawToolCall, ...]
    """The scripted calls with the proxy's call ids (`c1`, `c2`, ...) for an engine run."""


def library_item(item_id: str, seed: int) -> tuple[Scenario, tuple[ScriptedCall, ...], str | None]:
    """(poisoned scenario, scripted calls, the attack id or None for a control)."""
    if item_id.startswith("A"):
        scenario, scripted = attack_world(item_id, seed)
        return scenario, scripted, item_id
    scenario, scripted = control_world(item_id, seed)
    return scenario, scripted, None


def approval_entries(gateway: Gateway, decision: Decision, call_id: str) -> list[LedgerEntry]:
    """The ledger entries of an approved card, one per row, as the engine writes them."""
    proposal = next(
        e.event.proposal
        for e in gateway.chain
        if isinstance(e.event, CallProposed) and e.event.proposal.call_id == call_id
    )
    endorsement_id = next(
        e.event.endorsement.endorsement_id
        for e in reversed(gateway.chain)
        if isinstance(e.event, EndorsementRequested) and e.event.endorsement.call_id == call_id
    )
    entries: list[LedgerEntry] = []
    for row in decision.diff_card.rows if decision.diff_card is not None else ():
        value = gateway.store.get(proposal.args[row.param].id)
        assert value is not None
        entries.append(
            LedgerEntry(
                entry_id=f"led-{endorsement_id}-{row.param}",
                ledger="endorsed",
                key=f"{row.param}: {row.preview}",
                value=value.ref,
                unit=param_unit(proposal.tool, row.param) or "identifier",
                canonical=row.preview,
                source=UserEndorsedSource(kind="user_endorsed", endorsement_id=endorsement_id),
            )
        )
    return entries


def _decisions(gateway: Gateway, call_id: str) -> list[Decision]:
    return [
        e.event.decision
        for e in gateway.chain
        if isinstance(e.event, DecisionMade) and e.event.call_id == call_id
    ]


def _resolve(server: ProxyServer, call_id: str, escalation: EscalationMode) -> None:
    """Approve or reject the call's pending escalation until it is settled."""
    gateway = server.gateway
    approvals = 0
    while True:
        decision = _decisions(gateway, call_id)[-1]
        if decision.verdict != "ESCALATE":
            return
        endorsement_id = next(
            e.event.endorsement.endorsement_id
            for e in reversed(gateway.chain)
            if isinstance(e.event, EndorsementRequested) and e.event.endorsement.call_id == call_id
        )
        approve = escalation == "approve_all" and approvals < MAX_ESCALATION_ROUNDS
        if approve:
            approvals += 1
            outcome = gateway.approve(endorsement_id, approval_entries(gateway, decision, call_id))
        else:
            outcome = gateway.reject(endorsement_id)
        assert outcome is not None
        if not approve:
            return


def run_through_proxy(item_id: str, tmp_path: Path, *, seed: int = 0) -> ProxiedRun:
    """One attack (A1..A14) or control (B1..B4) through the proxy; see the module docstring."""
    scenario, scripted, attack_id = library_item(item_id, seed)
    escalation: EscalationMode = "reject" if attack_id is None else get_setup(attack_id).escalation
    dump = tmp_path / f"{item_id}-world.json"
    command = [
        sys.executable,
        "-m",
        "notary_server.world_mcp",
        "--scenario",
        scenario.scenario_id,
        "--seed",
        str(seed),
        "--dump-state",
        str(dump),
    ]
    if attack_id is not None:
        command += ["--attack", attack_id]
    config = proxy_config_for(scenario, command=command)
    client = StdioClient(config.server.command, cwd=tmp_path)
    calls: list[ProxiedCall] = []
    try:
        server = build_server(config, client, run_id=f"run-mcp-{item_id}", audit=None)
        for index, call in enumerate(scripted, start=1):
            answer = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "tools/call",
                    "params": {"name": call.tool, "arguments": dict(call.args)},
                }
            )
            assert answer is not None
            server.wait_for_drift_checks()
            response = answer["result"]
            assert isinstance(response, dict)
            call_id = f"c{index}"
            _resolve(server, call_id, escalation)
            calls.append(
                ProxiedCall(
                    call_id=call_id,
                    scripted=call,
                    response=response,
                    decisions=_decisions(server.gateway, call_id),
                )
            )
        gateway = server.gateway
    finally:
        client.close()
    return ProxiedRun(
        item_id=item_id,
        scenario=scenario,
        escalation=escalation,
        calls=calls,
        gateway=gateway,
        world_after=WorldState.model_validate_json(dump.read_text(encoding="utf-8")),
        engine_calls=tuple(
            RawToolCall(call_id=f"c{i}", tool=c.tool, args=dict(c.args))
            for i, c in enumerate(scripted, start=1)
        ),
    )
