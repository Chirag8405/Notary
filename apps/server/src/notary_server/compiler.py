"""The Intent Compiler: the user's request to a frozen `IntentContract`.

An LLM PROPOSES which tools the request needs, a marker per parameter, a budget, egress hosts and
the irreversible tools the user authorized; deterministic code DECIDES what is kept. The merge
rule of the sensitive-parameter table applies: a proposal can only tighten a floor, never relax
it, and anything the model invents (an unknown tool, host or authorization) is dropped. The model
sees the request and the tools' names and parameters only: never fetched content, and never tool
descriptions, which are third-party text (A10).
"""

import json
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Literal, cast

from pydantic import ValidationError

from notary_core.canon import canonical_json, sha256_hex
from notary_core.models import (
    EffectBudget,
    EndorseMarker,
    FreeMarker,
    IntentContract,
    LedgerMarker,
    LiteralMarker,
    Marker,
    NamedSourceMarker,
    NotaryModel,
    ToolScope,
)
from notary_core.pinning import ToolManifest, manifest_hash
from notary_core.policy.sensitive_params import (
    PolicyTable,
    effective_effect,
    effective_marker,
    param_policy,
)
from notary_server.llm import DEFAULT_MAX_TOKENS, DEFAULT_MODEL, LlmClient, LlmRequest
from notary_world.models import CassetteTurn

COMPILER_SYSTEM: str = (
    "You are the intent compiler of a security system. You receive the user's request and the "
    "tools that exist with their parameters. Reply with one JSON object and nothing else: "
    '{"tools": [{"tool": <name>, "params": [{"name": <parameter>, "marker": <marker or null>}]}], '
    '"budget": {"max_effects": <int>, "max_spend_cents": <int>, "max_egress_bytes": <int>, '
    '"max_call_amount_cents": <int>, "max_approvals": <int>}, '
    '"egress_hosts": [<bare lowercase domain>], "authorized_irreversible": [<tool name>]}. '
    'A marker is {"kind": "literal" | "named_source" | "ledger" | "endorse" | "free", '
    '"value": <text or null>, "source": <text or null>, "ledger": <text or null>}. '
    'Use "literal" only for a value the user typed and "named_source" only for a source the '
    "user named. Include only the tools the request needs. Authorize an irreversible tool only "
    "if the request asks for that action. Choose the smallest budget that fits the request."
)

BUDGET_CAPS: Mapping[str, int] = MappingProxyType(
    {
        "max_effects": 20,
        "max_spend_cents": 100000,
        "max_egress_bytes": 10000,
        "max_call_amount_cents": 100000,
        "max_approvals": 5,
    }
)
"""Hard upper bounds: the compiler cannot grant more, whatever the model asks for."""

DEFAULT_BUDGET: Mapping[str, int] = MappingProxyType(
    {
        "max_effects": 2,
        "max_spend_cents": 20000,
        "max_egress_bytes": 0,
        "max_call_amount_cents": 20000,
        "max_approvals": 3,
    }
)

REPLY_ERROR = "compiler reply is not a valid proposal"


class CompileError(ValueError):
    """The compiler could not produce a contract; the message never echoes the model's reply."""


class MarkerProposal(NotaryModel):
    kind: Literal["literal", "named_source", "ledger", "endorse", "free"]
    value: str | None
    source: str | None
    ledger: str | None


class ParamProposal(NotaryModel):
    name: str
    marker: MarkerProposal | None


class ToolProposal(NotaryModel):
    tool: str
    params: tuple[ParamProposal, ...]


class BudgetProposal(NotaryModel):
    """A field the model left out or set to 0 or less falls back to `DEFAULT_BUDGET`."""

    max_effects: int | None = None
    max_spend_cents: int | None = None
    max_egress_bytes: int | None = None
    max_call_amount_cents: int | None = None
    max_approvals: int | None = None


class CompilerOutput(NotaryModel):
    tools: tuple[ToolProposal, ...]
    budget: BudgetProposal = BudgetProposal()
    egress_hosts: tuple[str, ...]
    authorized_irreversible: tuple[str, ...]


class CompiledContract(NotaryModel):
    contract: IntentContract
    dropped: tuple[str, ...]
    """Proposal items discarded: `tool:<name>`, `host:<value>`, `authorize:<name>`."""


def _index(manifests: Sequence[ToolManifest]) -> dict[str, ToolManifest]:
    by_name: dict[str, ToolManifest] = {}
    for manifest in manifests:
        if manifest.name in by_name:
            raise CompileError(f"duplicate tool name: {manifest.name}")
        by_name[manifest.name] = manifest
    return by_name


def _schema_params(manifest: ToolManifest) -> tuple[str, ...]:
    """The parameter names of a tool: the keys of `properties` in its schema text."""
    try:
        data: object = json.loads(manifest.input_schema)
    except ValueError:
        return ()
    if not isinstance(data, dict):
        return ()
    properties = cast(dict[str, object], data).get("properties")
    if not isinstance(properties, dict):
        return ()
    return tuple(sorted(str(name) for name in cast(dict[str, object], properties)))


def build_compiler_request(
    request: str, manifests: Sequence[ToolManifest], policy: PolicyTable, *, model: str
) -> LlmRequest:
    """What the model sees: the request and, per tool, its parameters with unit and floor."""
    tools: list[dict[str, object]] = []
    for manifest in sorted(_index(manifests).values(), key=lambda m: m.name):
        params: list[dict[str, object]] = []
        for name in _schema_params(manifest):
            bound = param_policy(policy, manifest.name, name)
            params.append({"name": name, "unit": bound.unit, "floor": bound.floor.kind})
        tools.append({"name": manifest.name, "params": params})
    content = canonical_json({"request": request, "tools": tools})
    return LlmRequest(
        model=model,
        system=COMPILER_SYSTEM,
        messages=(CassetteTurn(role="user", content=content, tool_calls=()),),
        tools=(),
        max_tokens=DEFAULT_MAX_TOKENS,
    )


def _to_marker(proposal: MarkerProposal) -> Marker | None:
    """The core marker of a consistent proposal, else None (the floor then wins)."""
    match proposal.kind:
        case "literal":
            if proposal.value is None:
                return None
            return LiteralMarker(kind="literal", value=proposal.value)
        case "named_source":
            if not proposal.source:
                return None
            return NamedSourceMarker(kind="named_source", source=proposal.source)
        case "ledger":
            if not proposal.ledger:
                return None
            return LedgerMarker(kind="ledger", ledger=proposal.ledger)
        case "endorse":
            return EndorseMarker(kind="endorse")
        case "free":
            return FreeMarker(kind="free")


def _scope(
    manifest: ToolManifest, proposed: Mapping[str, Marker | None], policy: PolicyTable
) -> ToolScope:
    params = {
        name: effective_marker(policy, manifest.name, name, proposed.get(name))
        for name in _schema_params(manifest)
    }
    return ToolScope(
        tool=manifest.name,
        params=params,
        manifest_hash=manifest_hash(manifest),
        effect=effective_effect(policy, manifest.name, None),
    )


def _budget_value(name: str, wanted: int | None) -> int:
    """The proposed value clamped to the cap; missing, 0 or negative is the default (a 0 budget
    would block the very action the user asked for, and the model has no business granting
    itself less or more than the system's bounds)."""
    if wanted is None or wanted <= 0:
        return DEFAULT_BUDGET[name]
    return min(wanted, BUDGET_CAPS[name])


COMPANION_READS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {"pay_bill": ("read_inbox",), "send_money": ("read_inbox",)}
)
"""Read tools a payment tool cannot be used without: the bill is in the inbox. Added to every
contract that allows the payment tool, whatever the model proposed."""


PAYLOAD_EGRESS_BYTES: int = 100
"""The least egress budget of a contract that admits a free-text (`payload`) parameter. The
budget step counts every payload byte as egress, so with 0 even `reference: "December bill"` on a
payment would be blocked. 100 bytes fits a short reference and bounds what text can leave
through it; the readers check (confidentiality) still stops secrets whatever the budget."""


def _with_payload_egress(contract: IntentContract, policy: PolicyTable) -> IntentContract:
    admits_payload = any(
        param_policy(policy, scope.tool, name).kind == "payload"
        for scope in contract.allowed_tools
        for name in scope.params
    )
    if not admits_payload or contract.budget.max_egress_bytes >= PAYLOAD_EGRESS_BYTES:
        return contract
    budget = contract.budget.model_copy(update={"max_egress_bytes": PAYLOAD_EGRESS_BYTES})
    return contract.model_copy(update={"budget": budget})


def _required_params(manifest: ToolManifest) -> frozenset[str]:
    try:
        data: object = json.loads(manifest.input_schema)
    except ValueError:
        return frozenset()
    if not isinstance(data, dict):
        return frozenset()
    required = cast(dict[str, object], data).get("required")
    if not isinstance(required, list):
        return frozenset()
    return frozenset(str(name) for name in cast(list[object], required))


def with_optional_params(
    contract: IntentContract, manifests: Sequence[ToolManifest], policy: PolicyTable
) -> IntentContract:
    """The contract with every optional parameter of its tools allowed at its policy floor.

    `compile_contract` already lists every schema parameter of a tool it keeps; a hand-written
    contract (the scenarios) may name only the required ones, and then a benign model that fills
    an optional parameter such as `pay_bill.reference` is blocked at scope. This adds exactly the
    parameters the contract lacks, at `effective_marker(policy, tool, param, None)`, which is the
    table's floor: nothing is relaxed, a floor is never lowered, and an existing marker is kept.
    """
    by_name = _index(manifests)
    scopes: list[ToolScope] = []
    for scope in contract.allowed_tools:
        manifest = by_name.get(scope.tool)
        if manifest is None:
            scopes.append(scope)
            continue
        optional = _schema_params(manifest)
        required = _required_params(manifest)
        extra = {
            name: effective_marker(policy, scope.tool, name, None)
            for name in optional
            if name not in required and name not in scope.params
        }
        scopes.append(scope.model_copy(update={"params": {**scope.params, **extra}}))
    widened = contract.model_copy(update={"allowed_tools": tuple(scopes)})
    return _with_payload_egress(widened, policy)


def _valid_host(host: str) -> bool:
    return host != "" and host == host.lower() and not any(c in host for c in "/: \t\n@")


def _authorized(
    names: Sequence[str], scopes: Mapping[str, ToolScope], dropped: list[str]
) -> tuple[str, ...]:
    irreversible = {tool for tool, scope in scopes.items() if scope.effect == "irreversible"}
    kept: set[str] = set()
    for name in names:
        if name in irreversible:
            kept.add(name)
        else:
            dropped.append(f"authorize:{name}")
    return tuple(tool for tool in sorted(scopes) if tool in kept)


def _contract(
    request: str,
    scopes: Mapping[str, ToolScope],
    budget: EffectBudget,
    hosts: Sequence[str],
    authorized: Sequence[str],
) -> IntentContract:
    return IntentContract(
        contract_id=f"contract-{sha256_hex(request)[:12]}",
        user_intent=request,
        allowed_tools=tuple(scopes[tool] for tool in sorted(scopes)),
        budget=budget,
        egress_hosts=tuple(hosts),
        authorized_irreversible=tuple(authorized),
    )


def _assemble(
    request: str,
    output: CompilerOutput,
    by_name: Mapping[str, ToolManifest],
    policy: PolicyTable,
) -> CompiledContract:
    dropped: list[str] = []
    scopes: dict[str, ToolScope] = {}
    for proposal in output.tools:
        manifest = by_name.get(proposal.tool)
        if manifest is None:
            dropped.append(f"tool:{proposal.tool}")
            continue
        if proposal.tool in scopes:
            continue
        proposed: dict[str, Marker | None] = {}
        for param in proposal.params:
            if param.marker is not None:
                proposed.setdefault(param.name, _to_marker(param.marker))
        scopes[proposal.tool] = _scope(manifest, proposed, policy)
    hosts: list[str] = []
    for host in output.egress_hosts:
        if not _valid_host(host):
            dropped.append(f"host:{host}")
        elif host not in hosts:
            hosts.append(host)
    authorized = _authorized(output.authorized_irreversible, scopes, dropped)
    for tool in sorted(scopes):
        for companion in COMPANION_READS.get(tool, ()):
            manifest = by_name.get(companion)
            if manifest is not None and companion not in scopes:
                scopes[companion] = _scope(manifest, {}, policy)
    wanted = output.budget
    budget = EffectBudget(
        max_effects=_budget_value("max_effects", wanted.max_effects),
        max_spend_cents=_budget_value("max_spend_cents", wanted.max_spend_cents),
        max_egress_bytes=_budget_value("max_egress_bytes", wanted.max_egress_bytes),
        max_call_amount_cents=_budget_value("max_call_amount_cents", wanted.max_call_amount_cents),
        max_approvals=_budget_value("max_approvals", wanted.max_approvals),
    )
    contract = _with_payload_egress(_contract(request, scopes, budget, hosts, authorized), policy)
    return CompiledContract(contract=contract, dropped=tuple(dropped))


def compile_contract(
    request: str,
    manifests: Sequence[ToolManifest],
    client: LlmClient,
    *,
    policy: PolicyTable,
    model: str = DEFAULT_MODEL,
) -> CompiledContract:
    """One model call, then deterministic assembly; no retry and no silent fallback."""
    by_name = _index(manifests)
    turn = client.complete(build_compiler_request(request, manifests, policy, model=model))
    if turn.role != "assistant" or turn.tool_calls:
        raise CompileError(REPLY_ERROR)
    try:
        output = CompilerOutput.model_validate_json(turn.content)
    except ValidationError:
        raise CompileError(REPLY_ERROR) from None
    return _assemble(request, output, by_name, policy)


def offline_contract(
    request: str,
    manifests: Sequence[ToolManifest],
    tools: Sequence[str],
    *,
    policy: PolicyTable,
    authorize: Sequence[str] = (),
) -> IntentContract:
    """A contract with no LLM: the listed tools at their floors and the default budget."""
    by_name = _index(manifests)
    scopes: dict[str, ToolScope] = {}
    for name in tools:
        manifest = by_name.get(name)
        if manifest is None:
            raise CompileError(f"unknown tool: {name}")
        scopes[name] = _scope(manifest, {}, policy)
    budget = EffectBudget(
        max_effects=DEFAULT_BUDGET["max_effects"],
        max_spend_cents=DEFAULT_BUDGET["max_spend_cents"],
        max_egress_bytes=DEFAULT_BUDGET["max_egress_bytes"],
        max_call_amount_cents=DEFAULT_BUDGET["max_call_amount_cents"],
        max_approvals=DEFAULT_BUDGET["max_approvals"],
    )
    return _contract(request, scopes, budget, (), _authorized(authorize, scopes, []))
