from collections.abc import Mapping, Sequence

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from world_builders import contract_with

import notary_core.resolver as core_resolver
from notary_core.canon import sha256_hex
from notary_core.models import (
    DecisionUnit,
    EmailOrigin,
    EndorseMarker,
    FileOrigin,
    Integrity,
    IntentContract,
    Label,
    LedgerEntry,
    Origin,
    ResolvedValue,
    ToolOrigin,
    ToolScope,
    UserOrigin,
    ValueRef,
)
from notary_core.provenance import INTEGRITY_ORDER, normalize_readers
from notary_core.resolver import ArgumentResolver, canonical_args
from notary_world import executor as world_executor
from notary_world.cast import ACCOUNTANT_EMAIL, ATTACKER_IBAN, BILL_AMOUNT, BILLER_IBAN
from notary_world.executor import ArgRecord, DefaultArgResolver, RunRecord, execute_run
from notary_world.scenarios import (
    Scenario,
    legitimate_bill_scenario,
    poisoned_bill_scenario,
)
from notary_world.state import WorldState
from notary_world.tools import TOOL_SPECS, RawToolCall, default_manifest_hash, param_unit

ZW = chr(0x200B)
Case = tuple[Sequence[ResolvedValue], str, DecisionUnit | None]


def value(
    value_id: str,
    text: str,
    *,
    integrity: Integrity = "untrusted",
    readers: tuple[str, ...] = ("*",),
    origin: Origin | None = None,
    unit: DecisionUnit | None = None,
) -> ResolvedValue:
    label = Label(
        origin=origin or EmailOrigin(kind="email"),
        integrity=integrity,
        readers=normalize_readers(readers),
        span_pointer=None,
    )
    ref = ValueRef(id=value_id, label=label, content_hash=sha256_hex(text))
    return ResolvedValue(ref=ref, unit=unit, text=text)


def both(
    values: Sequence[ResolvedValue], raw: str, unit: DecisionUnit | None
) -> tuple[ResolvedValue, ResolvedValue]:
    store = {v.ref.id: v for v in values}
    before = dict(store)
    core = ArgumentResolver()(
        call_id="c2", tool="pay_bill", param="payee", raw=raw, unit=unit, store=store
    )
    world = DefaultArgResolver()(
        call_id="c2", tool="pay_bill", param="payee", raw=raw, unit=unit, store=store
    )
    assert store == before
    return core, world


BODY = f"Amount due: 120.00 EUR. Pay to IBAN {ATTACKER_IBAN}."
SECRET = value("s", "CODE-8841", readers=("user",), origin=FileOrigin(kind="file"))
LOWER_ZW = BILLER_IBAN[:12].lower() + ZW + BILLER_IBAN[12:].lower()

CORPUS: tuple[Case, ...] = (
    ((value("x", BILLER_IBAN),), BILLER_IBAN, None),  # rule 1, exact
    ((value("x", BILLER_IBAN),), f" {BILLER_IBAN.lower()} ", "iban"),  # rule 1, canonical form
    ((value("x", BILLER_IBAN),), LOWER_ZW, "iban"),  # rule 1, zero-width text
    ((value("x", BILLER_IBAN),), LOWER_ZW, None),  # same text, no unit: rule 3
    (
        (value("a", BILLER_IBAN, integrity="trusted"), value("z", BILLER_IBAN)),
        BILLER_IBAN,
        None,
    ),  # rule 1, lowest integrity wins
    ((value("b", BILLER_IBAN), value("c", BILLER_IBAN)), BILLER_IBAN, None),  # rule 1, id tie
    ((value("c1.m-dec.body", BODY),), f" {ATTACKER_IBAN} ", "iban"),  # rule 2, worked example
    (
        (value("m2", f"see {ATTACKER_IBAN}"), value("m1", f"also {ATTACKER_IBAN}!")),
        ATTACKER_IBAN,
        None,
    ),  # rule 2, id tie across sources
    (
        (value("a", f"pay {ATTACKER_IBAN}", integrity="trusted"), value("z", BODY)),
        ATTACKER_IBAN,
        "iban",
    ),  # rule 2, lowest integrity source
    ((value("s", "CODE-8841 and more", readers=("user",)),), "CODE-8841", None),  # rule 2, secret
    ((value("x", "abcdef"),), "abc", None),  # short text: rule 3
    ((), "hello world", None),  # rule 3, empty store
    ((SECRET,), "my code is CODE-8841", None),  # rule 3, quoted secret
    ((value("s", "abc", readers=("user",)),), "my abc is here", None),  # short secret
    (
        (
            value(
                "v-request",
                "Pay my December bill",
                integrity="trusted",
                origin=UserOrigin(kind="user"),
            ),
        ),
        "December",
        None,
    ),
    ((value("x", BODY),), "", None),  # empty raw
    ((value("x", BODY),), "   ", None),  # blank raw
    ((value("x", BODY), SECRET), f"  {ATTACKER_IBAN} CODE-8841 ", None),  # padded, mixed
)


@pytest.mark.invariant("I2")
def test_resolver_matches_the_default_arg_resolver() -> None:
    assert len(CORPUS) >= 12
    for values, raw, unit in CORPUS:
        core, world = both(values, raw, unit)
        assert core == world, (raw, unit)


TEXT_ALPHABET = "abc D1-"
ORIGINS: tuple[Origin, ...] = (
    EmailOrigin(kind="email"),
    FileOrigin(kind="file"),
    UserOrigin(kind="user"),
    ToolOrigin(kind="tool", name="t"),
)
READERS: tuple[tuple[str, ...], ...] = (("*",), ("user",), ("alex", "user"))
UNITS: tuple[DecisionUnit | None, ...] = (None, "iban", "identifier", "email")
short_text = st.text(alphabet=TEXT_ALPHABET, max_size=12)


@st.composite
def resolver_cases(draw: st.DrawFn) -> Case:
    texts = draw(st.lists(short_text, max_size=4))
    values = [
        value(
            f"s{i}",
            text,
            integrity=draw(st.sampled_from(INTEGRITY_ORDER)),
            readers=draw(st.sampled_from(READERS)),
            origin=draw(st.sampled_from(ORIGINS)),
        )
        for i, text in enumerate(texts)
    ]
    raw = draw(short_text)
    if texts and draw(st.booleans()):
        raw = draw(st.sampled_from(texts))
    if draw(st.booleans()):
        raw = f"{draw(st.sampled_from(('', ' ', '  ')))}{raw}{draw(st.sampled_from(('', ' ')))}"
    return values, raw, draw(st.sampled_from(UNITS))


@pytest.mark.invariant("I2")
@settings(max_examples=200, deadline=None)
@given(resolver_cases())
def test_resolver_matches_the_default_arg_resolver_property(case: Case) -> None:
    values, raw, unit = case
    core, world = both(values, raw, unit)
    assert core == world


def args_for(
    tool: str, texts: Mapping[str, str]
) -> tuple[dict[str, ResolvedValue], list[ArgRecord]]:
    values = {
        p: value(f"x.arg.{p}", t, origin=ToolOrigin(kind="tool", name="t"))
        for p, t in texts.items()
    }
    return values, [ArgRecord(param=p, value=v) for p, v in values.items()]


def assert_same_canonical(tool: str, texts: Mapping[str, str]) -> None:
    values, records = args_for(tool, texts)
    units: dict[str, DecisionUnit | None] = {p: param_unit(tool, p) for p in texts}
    assert canonical_args(values, units) == world_executor.judged_tool_args(tool, records)


CANONICAL_CASES: tuple[tuple[str, dict[str, str]], ...] = (
    ("pay_bill", {"payee": f" {LOWER_ZW} ", "amount": "EUR 120,00", "reference": " Dec "}),
    ("send_money", {"payee": BILLER_IBAN.lower(), "amount": "120"}),
    (
        "send_email",
        {
            "to": "Accountant@ACME.example",
            "cc": f" {ACCOUNTANT_EMAIL.upper()} ",
            "subject": " S ",
            "body": "B\n",
        },
    ),
    ("add_contact", {"name": " Alpha Consulting ", "iban": LOWER_ZW, "email": f"A{ZW}@B.example"}),
    ("create_event", {"attendees": f"{ACCOUNTANT_EMAIL.upper()},x@y.example", "title": " T "}),
    ("post_slack", {"channel": " General ", "text": "Hello  World"}),
    ("read_file", {"path": " secrets/2fa.txt "}),
    ("nope", {"x": " Anything ", "y": BILL_AMOUNT}),
)


@pytest.mark.invariant("I2")
def test_canonical_args_matches_judged_tool_args() -> None:
    assert len(CANONICAL_CASES) >= 6
    for tool, texts in CANONICAL_CASES:
        assert_same_canonical(tool, texts)


TOOLS_WITH_PARAMS = tuple(spec for spec in TOOL_SPECS if spec.params)
arg_text = st.text(alphabet=f"abAB09@.-,; {ZW}D", max_size=14)


@pytest.mark.invariant("I2")
@settings(max_examples=100, deadline=None)
@given(st.data())
def test_canonical_args_matches_judged_tool_args_property(data: st.DataObject) -> None:
    spec = data.draw(st.sampled_from(TOOLS_WITH_PARAMS))
    names = [p.name for p in spec.params]
    texts = data.draw(st.dictionaries(st.sampled_from(names), arg_text, min_size=1))
    assert_same_canonical(spec.name, texts)


@pytest.mark.invariant("I6")
def test_protocol_compatibility() -> None:
    core_side: core_resolver.ArgResolver = ArgumentResolver()
    world_side: world_executor.ArgResolver = ArgumentResolver()
    store = {"x": value("x", BODY)}
    core = core_side(call_id="c1", tool="t", param="p", raw=ATTACKER_IBAN, unit=None, store=store)
    world = world_side(call_id="c1", tool="t", param="p", raw=ATTACKER_IBAN, unit=None, store=store)
    assert core == world


def run_with(
    scenario: Scenario,
    calls: Sequence[RawToolCall],
    *,
    resolver: world_executor.ArgResolver | None,
    contract: IntentContract | None = None,
    ledger: Sequence[LedgerEntry] | None = None,
    world: WorldState | None = None,
    escalation: world_executor.EscalationMode = "reject",
) -> RunRecord:
    return execute_run(
        scenario=scenario.scenario_id,
        run_id=f"run-{scenario.scenario_id}",
        request=scenario.user_request,
        world=world or scenario.world,
        contract=contract or scenario.contract,
        ledger=scenario.ledger if ledger is None else ledger,
        calls=calls,
        session=scenario.session,
        resolver=resolver,
        escalation=escalation,
    )


@pytest.mark.attack("A3")
def test_core_resolver_drives_a_real_run() -> None:
    contract = contract_with(
        (
            ToolScope(
                tool="add_contact",
                params={"name": EndorseMarker(kind="endorse")},
                manifest_hash=default_manifest_hash("add_contact"),
                effect="write",
            ),
        )
    )
    add = RawToolCall(call_id="a1", tool="add_contact", args={"name": "Alpha Consulting"})
    legit = legitimate_bill_scenario()
    poisoned = poisoned_bill_scenario()
    for scenario in (poisoned, legit):
        default = run_with(scenario, scenario.calls, resolver=None)
        core = run_with(scenario, scenario.calls, resolver=ArgumentResolver())
        assert core.model_dump_json() == default.model_dump_json()
    default = run_with(
        legit, (add,), resolver=None, contract=contract, ledger=(), escalation="approve_all"
    )
    core = run_with(
        legit,
        (add,),
        resolver=ArgumentResolver(),
        contract=contract,
        ledger=(),
        escalation="approve_all",
    )
    assert [c.status for c in core.calls] == ["escalated", "executed"]
    assert core.model_dump_json() == default.model_dump_json()
