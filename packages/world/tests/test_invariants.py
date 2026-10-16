import re
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from builders import contract_with

from notary_core.audit import append
from notary_core.ledger import UserAuthoredAuthority
from notary_core.models import (
    AuditEntry,
    EndorseMarker,
    Event,
    FreeMarker,
    IntentContract,
    InvariantResult,
    LedgerEntry,
    Marker,
    ToolEffect,
    ToolScope,
)
from notary_core.monitor import Monitor
from notary_core.units import canonicalize
from notary_world.cast import (
    BILL_AMOUNT,
    BILLER_IBAN,
)
from notary_world.executor import (
    EscalationMode,
    RunRecord,
    execute_run,
    finish,
    start_run,
    write_ledger,
)
from notary_world.invariants import (
    INVARIANT_DEFINITIONS,
    check_invariants,
)
from notary_world.scenarios import (
    Scenario,
    legitimate_bill_scenario,
    make_ledger_entry,
    poisoned_bill_scenario,
)
from notary_world.tools import RawToolCall, default_manifest_hash

AuditAppend = Callable[[Sequence[AuditEntry], Event], tuple[AuditEntry, ...]]
IDS = ("I1", "I2", "I3", "I4", "I5", "I6")
ZW = "\u200b"
SECRET_PATH = "secrets/2fa.txt"


def all_six[F: Callable[..., object]](test: F) -> F:
    """Mark a test with every invariant id, one stacked marker per id."""
    for invariant in IDS:
        test = pytest.mark.invariant(invariant)(test)
    return test


def scope(tool: str, params: dict[str, Marker], effect: ToolEffect = "write") -> ToolScope:
    return ToolScope(
        tool=tool, params=params, manifest_hash=default_manifest_hash(tool), effect=effect
    )


def free(*params: str) -> dict[str, Marker]:
    return {p: FreeMarker(kind="free") for p in params}


def run(
    calls: Sequence[RawToolCall] | None = None,
    *,
    scenario: Scenario | None = None,
    contract: IntentContract | None = None,
    ledger: Sequence[LedgerEntry] | None = None,
    monitor: Monitor | None = None,
    escalation: EscalationMode = "reject",
    audit_append: AuditAppend = append,
) -> RunRecord:
    base = scenario or legitimate_bill_scenario()
    return execute_run(
        scenario=base.scenario_id,
        run_id=f"run-{base.scenario_id}",
        request=base.user_request,
        world=base.world,
        contract=contract or base.contract,
        ledger=base.ledger if ledger is None else ledger,
        calls=base.calls if calls is None else calls,
        session=base.session,
        monitor=monitor,
        escalation=escalation,
        audit_append=audit_append,
    )


def legit_run() -> RunRecord:
    return run()


def poisoned_run() -> RunRecord:
    return run(scenario=poisoned_bill_scenario())


def contact_contract() -> IntentContract:
    return contract_with((scope("add_contact", {"name": EndorseMarker(kind="endorse")}),))


def approve_all_run() -> RunRecord:
    add = RawToolCall(call_id="a1", tool="add_contact", args={"name": "Alpha Consulting"})
    return run([add], contract=contact_contract(), ledger=(), escalation="approve_all")


def read_inbox(call_id: str = "c1") -> RawToolCall:
    return RawToolCall(call_id=call_id, tool="read_inbox", args={})


def pay(call_id: str, payee: str, **extra: str) -> RawToolCall:
    return RawToolCall(
        call_id=call_id, tool="pay_bill", args={"payee": payee, "amount": BILL_AMOUNT, **extra}
    )


def details(record: RunRecord) -> list[tuple[str, bool, str]]:
    return [(r.id, r.passed, r.detail) for r in check_invariants(record)]


def assert_all_hold(record: RunRecord) -> None:
    assert details(record) == [(i, True, "holds") for i in IDS]


# Passing runs


def doc_rows() -> dict[str, str]:
    doc = Path(__file__).resolve().parents[3] / "docs" / "architecture.md"
    rows: dict[str, str] = {}
    for line in doc.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"\|\s*(I[1-6])\s*\|\s*(.+?)\s*\|", line.strip())
        if match:
            rows[match.group(1)] = re.sub(r"\*\*|__|`", "", match.group(2)).strip()
    return rows


@all_six
def test_definitions_match_the_architecture_doc() -> None:
    assert doc_rows() == dict(INVARIANT_DEFINITIONS)


@all_six
def test_legitimate_run_satisfies_all_six_invariants() -> None:
    assert_all_hold(legit_run())


@all_six
def test_check_invariants_order_and_ids() -> None:
    results = check_invariants(legit_run())
    assert all(isinstance(r, InvariantResult) for r in results)
    assert tuple(r.id for r in results) == IDS


@all_six
def test_blocked_attack_run_satisfies_all_six_invariants() -> None:
    record = poisoned_run()
    assert record.calls[1].decision.verdict == "BLOCK"
    assert_all_hold(record)


@pytest.mark.invariant("I4")
@pytest.mark.invariant("I1")
@pytest.mark.invariant("I2")
def test_approve_all_run_satisfies_all_six_invariants() -> None:
    record = approve_all_run()
    assert [c.status for c in record.calls] == ["escalated", "executed"]
    assert_all_hold(record)


@pytest.mark.invariant("I2")
@pytest.mark.invariant("I4")
def test_fake_iban_failing_mod97_does_not_trip_any_check() -> None:
    assert canonicalize("iban", BILLER_IBAN).valid is False
    assert_all_hold(legit_run())
    scenario = legitimate_bill_scenario()
    engine = start_run(
        run_id="run-write",
        scenario=scenario.scenario_id,
        request=scenario.user_request,
        world=scenario.world,
        contract=scenario.contract,
        ledger=scenario.ledger,
    )
    entry = make_ledger_entry("acct-acme", "accounts", "Acme", BILLER_IBAN, "iban")
    engine, written = write_ledger(engine, entry, UserAuthoredAuthority(kind="user_authored"))
    assert written
    _, record = finish(engine)
    assert record.ledger_snapshots[-1].cause == "user_write"
    assert_all_hold(record)


@pytest.mark.invariant("I6")
def test_results_are_deterministic_and_inputs_untouched() -> None:
    record = legit_run()
    before = record.model_dump_json()
    first = check_invariants(record)
    second = check_invariants(record)
    assert [r.model_dump_json() for r in first] == [r.model_dump_json() for r in second]
    assert record.model_dump_json() == before
