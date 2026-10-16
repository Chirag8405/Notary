"""Shared builders for the agent-runner and lane tests: scripted turns, scenarios, run helpers."""

from collections.abc import Generator, Sequence

from notary_core.audit import append
from notary_core.models import (
    EffectBudget,
    EndorseMarker,
    Event,
    IntentContract,
    Lane,
    OracleUpdated,
    ToolScope,
)
from notary_core.runner import RunnerHooks, hooks_for_lane
from notary_server.agent_runner import (
    ContractSource,
    EscalationDecider,
    ServerAgentRunner,
    reject_all,
    scenario_contract,
)
from notary_server.llm import LlmClient, ScriptedClient
from notary_world.cast import ATTACKER_IBAN, BILL_AMOUNT, BILLER_IBAN
from notary_world.classifier import ClassifierFilter
from notary_world.executor import AuditAppend, RunRecord, default_monitor
from notary_world.models import CassetteToolCall, CassetteTurn
from notary_world.poison import PoisonConfig, apply_poison
from notary_world.scenarios import Scenario, get_scenario, legitimate_bill_scenario
from notary_world.tools import default_manifest_hash

__all__ = [
    "FINAL",
    "PAY_ACME",
    "PAY_ATTACKER",
    "READ_INBOX",
    "assistant",
    "catalog",
    "contact_scenario",
    "drain",
    "hooks_for",
    "injected_scenario",
    "last_oracle",
    "notary_hooks",
    "run_lane",
    "tool_messages",
    "types_collapsed",
]


def assistant(*calls: tuple[str, dict[str, str]], content: str = "") -> CassetteTurn:
    return CassetteTurn(
        role="assistant",
        content=content,
        tool_calls=tuple(CassetteToolCall(tool=t, args=a) for t, a in calls),
    )


FINAL = assistant(content="Done.")
READ_INBOX = assistant(("read_inbox", {}))
PAY_ACME = assistant(("pay_bill", {"payee": BILLER_IBAN, "amount": BILL_AMOUNT}))
PAY_ATTACKER = assistant(("pay_bill", {"payee": ATTACKER_IBAN, "amount": BILL_AMOUNT}))


def contact_scenario(max_approvals: int = 3) -> Scenario:
    contract = IntentContract(
        contract_id="contract-contacts",
        user_intent="Save my new contacts",
        allowed_tools=(
            ToolScope(
                tool="add_contact",
                params={"name": EndorseMarker(kind="endorse")},
                manifest_hash=default_manifest_hash("add_contact"),
                effect="write",
            ),
        ),
        budget=EffectBudget(
            max_effects=10,
            max_spend_cents=20000,
            max_egress_bytes=10000,
            max_call_amount_cents=20000,
            max_approvals=max_approvals,
        ),
        egress_hosts=(),
        authorized_irreversible=(),
    )
    base = legitimate_bill_scenario()
    return base.model_copy(update={"scenario_id": "contacts", "contract": contract, "ledger": ()})


def injected_scenario() -> Scenario:
    config = PoisonConfig(
        slot="email_body", kind="instruction", target_id=None, payload=None, iban=None
    )
    base = legitimate_bill_scenario()
    return base.model_copy(update={"world": apply_poison(base.world, config)})


def catalog(name: str) -> Scenario:
    if name == "contacts":
        return contact_scenario()
    if name == "contacts1":
        return contact_scenario(max_approvals=1)
    if name == "injected":
        return injected_scenario()
    return get_scenario(name)


def drain(run: Generator[Event, None, RunRecord]) -> tuple[list[Event], RunRecord]:
    events: list[Event] = []
    while True:
        try:
            events.append(next(run))
        except StopIteration as stop:
            return events, stop.value


def notary_hooks() -> RunnerHooks:
    return hooks_for_lane("notary", gate=default_monitor())


def hooks_for(lane: Lane) -> RunnerHooks:
    if lane == "undefended":
        return hooks_for_lane("undefended")
    if lane == "classifier":
        return hooks_for_lane("classifier", classifier_filter=ClassifierFilter())
    return notary_hooks()


def run_lane(
    client: LlmClient,
    scenario: str = "legitimate_bill",
    lane: Lane = "notary",
    *,
    decider: EscalationDecider = reject_all,
    contracts: ContractSource = scenario_contract,
    audit_append: AuditAppend = append,
) -> tuple[list[Event], RunRecord]:
    runner = ServerAgentRunner(
        llm=client,
        scenarios=catalog,
        decide_escalation=decider,
        contracts=contracts,
        audit_append=audit_append,
    )
    run = runner.run(
        lane=lane, scenario=scenario, run_id=f"run-{scenario}-{lane}", hooks=hooks_for(lane)
    )
    return drain(run)


def types_collapsed(events: Sequence[Event]) -> list[str]:
    out: list[str] = []
    for event in events:
        if event.type == "value_labeled" and out and out[-1] == "value_labeled":
            continue
        out.append(event.type)
    return out


def last_oracle(events: Sequence[Event]) -> OracleUpdated:
    return [e for e in events if isinstance(e, OracleUpdated)][-1]


def tool_messages(client: ScriptedClient) -> list[str]:
    last = client.requests[-1].messages
    return [m.content for m in last if m.role == "tool"]
