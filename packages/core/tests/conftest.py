"""Shared fixtures (factory callables), I/A markers and the I/A coverage summary."""

import hashlib
from collections.abc import Callable

import pytest
from _pytest.terminal import TerminalReporter

from notary_core.models import (
    DecisionUnit,
    EffectBudget,
    EmailOrigin,
    FileOrigin,
    FreeMarker,
    Integrity,
    IntentContract,
    Label,
    LedgerEntry,
    LedgerOrigin,
    LedgerSource,
    LlmOrigin,
    Marker,
    Origin,
    ResolvedValue,
    SessionState,
    SpanPointer,
    ToolCallProposal,
    ToolEffect,
    ToolOrigin,
    ToolScope,
    UserAuthoredSource,
    UserOrigin,
    ValueRef,
    WebOrigin,
)
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import DEFAULT_POLICY, PolicyTable

VALID_INVARIANTS = {f"I{i}" for i in range(1, 7)}
VALID_ATTACKS = {f"A{i}" for i in range(1, 15)}

_MARKER_IDS = {"invariant": VALID_INVARIANTS, "attack": VALID_ATTACKS}
_COVERED_KEY = pytest.StashKey[set[str]]()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _origin(name: str) -> Origin:
    """Parse "user" | "email" | "file" | "web" | "ledger" | "llm" | "tool:<name>"."""
    if name.startswith("tool:"):
        return ToolOrigin(kind="tool", name=name.removeprefix("tool:"))
    simple: dict[str, Origin] = {
        "user": UserOrigin(kind="user"),
        "email": EmailOrigin(kind="email"),
        "file": FileOrigin(kind="file"),
        "web": WebOrigin(kind="web"),
        "ledger": LedgerOrigin(kind="ledger"),
        "llm": LlmOrigin(kind="llm", context_readers=("*",)),
    }
    if name not in simple:
        raise ValueError(f"unknown origin {name!r}")
    return simple[name]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "invariant(id): test covers invariant I1-I6")
    config.addinivalue_line("markers", "attack(id): test covers attack A1-A14")
    config.stash[_COVERED_KEY] = set()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    covered = config.stash[_COVERED_KEY]
    for item in items:
        for name, valid in _MARKER_IDS.items():
            for marker in item.iter_markers(name):
                if not marker.args:
                    raise pytest.UsageError(f"{item.nodeid}: {name} marker needs an id")
                for arg in marker.args:
                    if arg not in valid:
                        raise pytest.UsageError(f"unknown id {arg}")
                    covered.add(arg)


def pytest_terminal_summary(terminalreporter: TerminalReporter) -> None:
    covered: set[str] = terminalreporter.config.stash.get(_COVERED_KEY, set[str]())
    universe = sorted(VALID_INVARIANTS | VALID_ATTACKS, key=lambda i: (i[0], int(i[1:])))
    hit = [i for i in universe if i in covered]
    missed = [i for i in universe if i not in covered]
    terminalreporter.write_line(
        f"I/A coverage: {' '.join(hit) or '-'} | uncovered: {' '.join(missed) or '-'}"
    )


@pytest.fixture
def make_label() -> Callable[..., Label]:
    def factory(
        origin: str = "user",
        integrity: Integrity = "trusted",
        readers: tuple[str, ...] = ("*",),
        span: SpanPointer | None = None,
    ) -> Label:
        return Label(
            origin=_origin(origin), integrity=integrity, readers=readers, span_pointer=span
        )

    return factory


@pytest.fixture
def make_value(make_label: Callable[..., Label]) -> Callable[..., ResolvedValue]:
    def factory(
        id: str,
        text: str,
        unit: DecisionUnit | None = None,
        origin: str = "user",
        integrity: Integrity = "trusted",
        readers: tuple[str, ...] = ("*",),
    ) -> ResolvedValue:
        label = make_label(origin=origin, integrity=integrity, readers=readers)
        ref = ValueRef(id=id, label=label, content_hash=_sha(text))
        return ResolvedValue(ref=ref, unit=unit, text=text)

    return factory


@pytest.fixture
def make_scope() -> Callable[..., ToolScope]:
    def factory(
        tool: str,
        effect: ToolEffect = "write",
        params: dict[str, Marker] | None = None,
        manifest_hash: str | None = None,
    ) -> ToolScope:
        return ToolScope.model_validate(
            {
                "tool": tool,
                "params": {"amount": FreeMarker(kind="free")} if params is None else params,
                "manifest_hash": manifest_hash or _sha(tool),
                "effect": effect,
            }
        )

    return factory


@pytest.fixture
def make_contract() -> Callable[..., IntentContract]:
    def factory(
        tools: tuple[ToolScope, ...] = (),
        budget: EffectBudget | None = None,
        egress_hosts: tuple[str, ...] = (),
        authorized_irreversible: tuple[str, ...] = (),
    ) -> IntentContract:
        return IntentContract(
            contract_id="c1",
            user_intent="test intent",
            allowed_tools=tools,
            budget=budget
            or EffectBudget(
                max_effects=10,
                max_spend_cents=1_000_000,
                max_egress_bytes=1_000_000,
                max_call_amount_cents=1_000_000,
                max_approvals=10,
            ),
            egress_hosts=egress_hosts,
            authorized_irreversible=authorized_irreversible,
        )

    return factory


@pytest.fixture
def make_proposal() -> Callable[..., ToolCallProposal]:
    def factory(
        tool: str, call_id: str = "call-1", manifest_hash: str | None = None, **args: ResolvedValue
    ) -> ToolCallProposal:
        return ToolCallProposal(
            call_id=call_id,
            tool=tool,
            manifest_hash=manifest_hash or _sha(tool),
            args={name: value.ref for name, value in args.items()},
        )

    return factory


@pytest.fixture
def make_ledger_entry() -> Callable[..., LedgerEntry]:
    def factory(
        value: ResolvedValue,
        unit: DecisionUnit,
        canonical: str,
        ledger: str = "payees",
        key: str = "Acme",
        entry_id: str = "e1",
        source: LedgerSource | None = None,
    ) -> LedgerEntry:
        return LedgerEntry(
            entry_id=entry_id,
            ledger=ledger,
            key=key,
            value=value.ref,
            unit=unit,
            canonical=canonical,
            source=source or UserAuthoredSource(kind="user_authored"),
        )

    return factory


@pytest.fixture
def make_session() -> Callable[..., SessionState]:
    def factory(
        spent_cents: int = 0,
        effects_used: int = 0,
        egress_bytes_used: int = 0,
        approvals_used: int = 0,
    ) -> SessionState:
        return SessionState(
            spent_cents=spent_cents,
            effects_used=effects_used,
            egress_bytes_used=egress_bytes_used,
            approvals_used=approvals_used,
        )

    return factory


@pytest.fixture
def make_input(
    make_contract: Callable[..., IntentContract],
    make_scope: Callable[..., ToolScope],
    make_proposal: Callable[..., ToolCallProposal],
    make_session: Callable[..., SessionState],
) -> Callable[..., StepInput]:
    def factory(
        tool: str = "pay_bill",
        *,
        effect: ToolEffect = "write",
        args: dict[str, ResolvedValue] | None = None,
        contract: IntentContract | None = None,
        ledger: tuple[LedgerEntry, ...] = (),
        session: SessionState | None = None,
        policy: PolicyTable = DEFAULT_POLICY,
        prior_escalated: bool = False,
        manifest_hash: str | None = None,
    ) -> StepInput:
        """A `StepInput` for `tool`; by default the contract allows exactly that tool."""
        tool_scope = make_scope(tool, effect=effect)
        the_contract = contract or make_contract(tools=(tool_scope,))
        resolved = {} if args is None else args
        return StepInput(
            contract=the_contract,
            proposal=make_proposal(tool, manifest_hash=manifest_hash, **resolved),
            values={value.ref.id: value for value in resolved.values()},
            ledger=ledger,
            session=session or make_session(),
            scope=next((t for t in the_contract.allowed_tools if t.tool == tool), None),
            policy=policy,
            prior_escalated=prior_escalated,
        )

    return factory
