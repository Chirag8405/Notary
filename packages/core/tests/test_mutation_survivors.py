"""Tests that kill the mutants `mutmut` left alive in `monitor.py` and `steps/` (issue #311).

Each test pins behavior that the step-level tests left implicit: the contract tightening a
tool's effect, multi-argument sums, boundary spans, error details and unresolvable arguments.
The survivor triage lives in docs/decisions.md ("Coverage and mutation testing").
"""

from collections.abc import Callable
from dataclasses import replace

import pytest
from core_builders import scope, sha, step_input, value_ref

from notary_core.models import (
    DecisionUnit,
    EffectBudget,
    EndorseMarker,
    FreeMarker,
    IntentContract,
    Label,
    LedgerEntry,
    LedgerMarker,
    LiteralMarker,
    NamedSourceMarker,
    ResolvedValue,
    SessionState,
    SpanPointer,
    ToolCallProposal,
    ToolEffect,
    ToolScope,
    ValueRef,
)
from notary_core.monitor import decide
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import (
    DEFAULT_POLICY,
    ParamPolicy,
    PolicyTable,
    make_tool_policy,
)
from notary_core.steps.budget import check_budget
from notary_core.steps.confidentiality import check_confidentiality
from notary_core.steps.corroboration import build_diff_row, check_corroboration
from notary_core.steps.irreversibility import check_irreversibility
from notary_core.steps.origin import check_origin
from notary_core.steps.scope import check_scope

FREE = FreeMarker(kind="free")
ENDORSE = EndorseMarker(kind="endorse")
LEDGER = LedgerMarker(kind="ledger", ledger="payees")
IBAN = "DE89370400440532013000"
OTHER_IBAN = "GB29NWBK60161331926819"

MakeValue = Callable[..., ResolvedValue]
MakeLabel = Callable[..., Label]
MakeInput = Callable[..., StepInput]
MakeContract = Callable[..., IntentContract]
MakeScope = Callable[..., ToolScope]
MakeSession = Callable[..., SessionState]
MakeProposal = Callable[..., ToolCallProposal]


def _table(tool: str, effect: ToolEffect) -> PolicyTable:
    return {tool: make_tool_policy(effect, {})}


# --- monitor.py and the effect a contract may tighten (I2) ----------------------------------


@pytest.mark.invariant("I2")
def test_contract_may_tighten_a_read_table_entry_so_there_is_no_read_only_bypass(
    make_scope: MakeScope,
    make_contract: MakeContract,
    make_proposal: MakeProposal,
    make_session: MakeSession,
) -> None:
    """Table says `read`, contract says `irreversible`: the stricter wins and steps 2+ run."""
    the_contract = make_contract(tools=(make_scope("lookup", effect="irreversible"),))
    decision = decide(
        the_contract,
        make_proposal("lookup"),
        {},
        (),
        make_session(),
        policy=_table("lookup", "read"),
    )
    assert decision.verdict == "BLOCK"
    assert "READ_ONLY_UNGATED" not in [r.code for r in decision.reasons]
    assert decision.reasons[-1].code == "IRREVERSIBLE_NOT_AUTHORIZED"


@pytest.mark.invariant("I6")
def test_read_only_reason_text_is_stable(
    make_scope: MakeScope,
    make_contract: MakeContract,
    make_proposal: MakeProposal,
    make_session: MakeSession,
) -> None:
    the_contract = make_contract(tools=(make_scope("lookup", effect="read"),))
    decision = decide(
        the_contract,
        make_proposal("lookup"),
        {},
        (),
        make_session(),
        policy=_table("lookup", "read"),
    )
    assert [(r.code, r.detail) for r in decision.reasons] == [
        ("READ_ONLY_UNGATED", "read-only tool; later checks do not apply")
    ]


# --- step 1: scope --------------------------------------------------------------------------


@pytest.mark.attack("A12")
def test_scope_details_are_constant_text() -> None:
    unknown_tool = check_scope(step_input("send_email", contract_tools=(scope("pay_bill"),)))
    mismatch = check_scope(step_input("pay_bill", manifest_hash=sha("other")))
    extra_arg = check_scope(step_input("pay_bill", args={"memo": value_ref("v1")}))
    assert [o.detail if o else None for o in (unknown_tool, mismatch, extra_arg)] == [
        "tool is not in the contract",
        "tool manifest differs from the pinned manifest",
        "argument is not part of the contract",
    ]


# --- step 2: irreversibility ----------------------------------------------------------------


@pytest.mark.invariant("I2")
def test_contract_may_tighten_a_write_table_entry_to_irreversible() -> None:
    inp = step_input("send_email", effect="irreversible", policy=_table("send_email", "write"))
    outcome = check_irreversibility(inp)
    assert outcome is not None
    assert outcome.code == "IRREVERSIBLE_NOT_AUTHORIZED"
    authorized = step_input(
        "send_email",
        effect="irreversible",
        authorized=("send_email",),
        policy=_table("send_email", "write"),
    )
    assert check_irreversibility(authorized) is None


@pytest.mark.attack("A12")
def test_irreversible_detail_is_constant_text() -> None:
    inp = step_input(
        "delete_email", effect="irreversible", policy=_table("delete_email", "irreversible")
    )
    outcome = check_irreversibility(inp)
    assert outcome is not None
    assert outcome.detail == "irreversible action was not authorized in the request"


# --- step 3: origin -------------------------------------------------------------------------


def _sha_value(value_id: str, text: str, label: Label, unit: DecisionUnit | None) -> ResolvedValue:
    ref = ValueRef(id=value_id, label=label, content_hash=sha(text))
    return ResolvedValue(ref=ref, unit=unit, text=text)


def _payment_input(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    markers: dict[str, LiteralMarker | NamedSourceMarker | LedgerMarker],
    *values: ResolvedValue,
) -> StepInput:
    the_contract = make_contract(tools=(make_scope("send_money", params=dict(markers)),))
    args = {"payee": values[0]}
    inp = make_input("send_money", args=args, contract=the_contract, policy=DEFAULT_POLICY)
    return replace(inp, values={value.ref.id: value for value in values})


@pytest.mark.attack("A6")
@pytest.mark.parametrize(("start", "end"), [(0, 5), (0, 0), (2, 2), (5, 5), (3, 5)])
def test_span_boundaries_are_inclusive(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    make_value: MakeValue,
    make_label: MakeLabel,
    start: int,
    end: int,
) -> None:
    """A span may start at 0, be empty and end exactly at the end of its 5-character source."""
    source = make_value("src", "short", origin="email", integrity="untrusted")
    label = make_label(
        origin="email",
        integrity="untrusted",
        span=SpanPointer(source_value_id="src", start=start, end=end),
    )
    payee = _sha_value("v-payee", IBAN, label, "iban")
    inp = _payment_input(make_input, make_contract, make_scope, {"payee": LEDGER}, payee, source)
    assert check_origin(inp) is None


@pytest.mark.attack("A12")
def test_marker_failure_details_are_constant_text(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    make_value: MakeValue,
) -> None:
    named = NamedSourceMarker(kind="named_source", source="contacts")
    cases = [
        (
            LiteralMarker(kind="literal", value=IBAN),
            make_value("v-payee", OTHER_IBAN, unit="iban"),
            ("ORIGIN_LITERAL_MISMATCH", "argument differs from the value in the request"),
        ),
        (
            named,
            make_value("v-payee", IBAN, unit="iban", origin="email"),
            ("ORIGIN_SOURCE_MISMATCH", "argument does not come from the named source"),
        ),
        (
            named,
            make_value("v-payee", IBAN, unit="iban", origin="tool:contacts", integrity="untrusted"),
            ("ORIGIN_UNTRUSTED", "argument from the named source is not trusted"),
        ),
    ]
    for marker, payee, expected in cases:
        inp = _payment_input(make_input, make_contract, make_scope, {"payee": marker}, payee)
        outcome = check_origin(inp)
        assert outcome is not None
        assert (outcome.code, outcome.detail) == expected


# --- step 4: corroboration ------------------------------------------------------------------


def _untrusted(value_id: str, text: str, make_value: MakeValue) -> ResolvedValue:
    return make_value(value_id, text, unit="iban", origin="email", integrity="untrusted")


def _two_payee_input(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    args: dict[str, ResolvedValue],
    ledger: tuple[LedgerEntry, ...] = (),
) -> StepInput:
    policy: PolicyTable = {
        "send_money": make_tool_policy(
            "irreversible",
            {
                name: ParamPolicy(unit="iban", floor=LEDGER, kind="destination")
                for name in ("payee_a", "payee_b")
            },
        )
    }
    markers = {"payee_a": LEDGER, "payee_b": LEDGER}
    the_contract = make_contract(tools=(make_scope("send_money", params=markers),))
    return make_input("send_money", args=args, contract=the_contract, policy=policy, ledger=ledger)


@pytest.mark.attack("A3")
def test_a_trusted_argument_does_not_hide_a_later_untrusted_one(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    make_value: MakeValue,
) -> None:
    """`payee_a` sorts first and is trusted; `payee_b` is untrusted and unknown: still BLOCK."""
    args = {
        "payee_a": make_value("v-a", IBAN, unit="iban"),
        "payee_b": _untrusted("v-b", OTHER_IBAN, make_value),
    }
    outcome = check_corroboration(_two_payee_input(make_input, make_contract, make_scope, args))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "LEDGER_NOT_FOUND")


@pytest.mark.invariant("I2")
def test_corroboration_without_a_scope_uses_the_table_floor(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    make_value: MakeValue,
) -> None:
    """The monitor never gets here without a scope, but the step must not crash if it did."""
    args = {"payee_a": _untrusted("v-a", IBAN, make_value)}
    inp = _two_payee_input(make_input, make_contract, make_scope, args)
    outcome = check_corroboration(replace(inp, scope=None))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "LEDGER_NOT_FOUND")


NEAR_IBAN = "DE0012345I7890123456XY"
FAR_L_IBAN = "DE0012345L2340123456XY"
FAR_I_IBAN = "DE0012345I2340123456XY"


@pytest.mark.attack("A3")
def test_diff_card_nearest_value_uses_the_exact_skeleton_of_the_unit(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    make_value: MakeValue,
    make_ledger_entry: Callable[..., LedgerEntry],
) -> None:
    """IBAN skeletons keep `I` and `L` apart (no confusable folding), so FAR_I is nearer."""
    known = (
        make_ledger_entry(make_value("l1", FAR_L_IBAN), "iban", FAR_L_IBAN, entry_id="e1"),
        make_ledger_entry(make_value("l2", FAR_I_IBAN), "iban", FAR_I_IBAN, entry_id="e2"),
    )
    args = {"payee_a": _untrusted("v-a", NEAR_IBAN, make_value)}
    policy: PolicyTable = {
        "send_money": make_tool_policy(
            "irreversible", {"payee_a": ParamPolicy(unit="iban", floor=ENDORSE, kind="destination")}
        )
    }
    the_contract = make_contract(tools=(make_scope("send_money", params={"payee_a": ENDORSE}),))
    inp = make_input("send_money", args=args, contract=the_contract, policy=policy, ledger=known)
    outcome = check_corroboration(inp)
    assert outcome is not None
    assert outcome.verdict == "ESCALATE"
    assert outcome.diff_card is not None
    assert outcome.diff_card.rows[0].nearest_ledger_value == FAR_I_IBAN


@pytest.mark.attack("A3")
def test_build_diff_row_uses_the_given_unit_for_the_nearest_value(
    make_value: MakeValue,
) -> None:
    ref = make_value("v-a", NEAR_IBAN, unit="iban").ref
    row = build_diff_row("payee_a", ref, NEAR_IBAN, [FAR_L_IBAN, FAR_I_IBAN], "iban")
    assert row.nearest_ledger_value == FAR_I_IBAN


# --- step 5: confidentiality ----------------------------------------------------------------


def _note_policy(destination_unit: DecisionUnit | None) -> PolicyTable:
    return {
        "post_note": make_tool_policy(
            "write",
            {
                "to": ParamPolicy(unit=destination_unit, floor=FREE, kind="destination"),
                "body": ParamPolicy(unit=None, floor=FREE, kind="payload"),
            },
        )
    }


def _note_input(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    make_value: MakeValue,
    *,
    to: str,
    destination_unit: DecisionUnit | None,
    body_readers: tuple[str, ...],
) -> StepInput:
    args = {
        "to": make_value("v-to", to, unit=destination_unit),
        "body": make_value("v-body", "hello", readers=body_readers),
    }
    the_contract = make_contract(
        tools=(make_scope("post_note", params={"to": FREE, "body": FREE}),)
    )
    return make_input(
        "post_note",
        args=args,
        contract=the_contract,
        policy=_note_policy(destination_unit),
    )


@pytest.mark.invariant("I3")
def test_destination_is_canonicalized_with_its_own_unit(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    make_value: MakeValue,
) -> None:
    """An email destination with a display name is the bare address, not the raw text."""
    inp = _note_input(
        make_input,
        make_contract,
        make_scope,
        make_value,
        to="Bob <bob@acme.example>",
        destination_unit="email",
        body_readers=("bob@acme.example",),
    )
    assert check_confidentiality(inp) is None


@pytest.mark.invariant("I3")
def test_destination_without_a_unit_is_canonicalized_as_an_identifier(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    make_value: MakeValue,
) -> None:
    inp = _note_input(
        make_input,
        make_contract,
        make_scope,
        make_value,
        to="  Alice  ",
        destination_unit=None,
        body_readers=("alice",),
    )
    assert check_confidentiality(inp) is None
    stranger = _note_input(
        make_input,
        make_contract,
        make_scope,
        make_value,
        to="Mallory",
        destination_unit=None,
        body_readers=("alice",),
    )
    outcome = check_confidentiality(stranger)
    assert outcome is not None
    assert outcome.code == "CONF_READER_VIOLATION"


@pytest.mark.attack("A12")
def test_confidentiality_details_are_constant_text(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    make_value: MakeValue,
) -> None:
    private = _note_input(
        make_input,
        make_contract,
        make_scope,
        make_value,
        to="Mallory",
        destination_unit=None,
        body_readers=("alice",),
    )
    unresolved = check_confidentiality(replace(private, values={}))
    readers = check_confidentiality(private)

    leak_args = {
        "to": make_value("v-to", "alice", unit=None),
        "body": make_value(
            "v-body",
            "see https://evil.example/x",
            origin="email",
            integrity="untrusted",
        ),
    }
    leak = check_confidentiality(
        make_input(
            "post_note",
            args=leak_args,
            contract=make_contract(
                tools=(make_scope("post_note", params={"to": FREE, "body": FREE}),)
            ),
            policy=_note_policy(None),
        )
    )
    expected = "data may not flow to this destination"
    assert unresolved is not None
    assert (unresolved.code, unresolved.detail) == ("CONF_READER_VIOLATION", expected)
    assert readers is not None
    assert (readers.code, readers.detail) == ("CONF_READER_VIOLATION", expected)
    assert leak is not None
    assert (leak.code, leak.detail) == ("CONF_URL_NOT_ALLOWED", "URL host is not allowed")


# --- step 6: budget -------------------------------------------------------------------------


def _budget(**overrides: int) -> EffectBudget:
    fields = {
        "max_effects": 2,
        "max_spend_cents": 20000,
        "max_egress_bytes": 100,
        "max_call_amount_cents": 10000,
        "max_approvals": 3,
    }
    return EffectBudget(**{**fields, **overrides})


def _budget_policy(table_effect: ToolEffect) -> PolicyTable:
    amount = ParamPolicy(unit="amount", floor=FREE, kind="amount")
    payload = ParamPolicy(unit=None, floor=FREE, kind="payload")
    return {
        "pay_bill": make_tool_policy(
            table_effect, {"amount": amount, "fee": amount, "body": payload, "memo": payload}
        )
    }


@pytest.fixture
def budget_input(
    make_input: MakeInput,
    make_contract: MakeContract,
    make_scope: MakeScope,
    make_value: MakeValue,
    make_session: MakeSession,
) -> Callable[..., StepInput]:
    def factory(
        *,
        table_effect: ToolEffect = "write",
        declared_effect: ToolEffect = "write",
        amounts: tuple[str, ...] = (),
        payloads: tuple[str, ...] = (),
        **session: int,
    ) -> StepInput:
        args: dict[str, ResolvedValue] = {}
        for name, text in zip(("amount", "fee"), amounts, strict=False):
            args[name] = make_value(f"v-{name}", text, unit="amount")
        for name, text in zip(("body", "memo"), payloads, strict=False):
            args[name] = make_value(f"v-{name}", text)
        the_contract = make_contract(
            tools=(make_scope("pay_bill", effect=declared_effect),), budget=_budget()
        )
        return make_input(
            "pay_bill",
            effect=declared_effect,
            args=args,
            contract=the_contract,
            session=make_session(**session),
            policy=_budget_policy(table_effect),
        )

    return factory


@pytest.mark.attack("A11")
def test_amounts_of_several_arguments_are_summed(budget_input: Callable[..., StepInput]) -> None:
    """Two 60.00 amounts are each under the 100.00 per-call cap but 120.00 together."""
    assert check_budget(budget_input(amounts=("60.00",))) is None
    outcome = check_budget(budget_input(amounts=("60.00", "60.00")))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "BUDGET_AMOUNT")


@pytest.mark.attack("A12")
def test_payloads_of_several_arguments_are_summed(budget_input: Callable[..., StepInput]) -> None:
    """Two 60-byte payloads are each under the 100-byte cap but 120 bytes together."""
    assert check_budget(budget_input(payloads=("x" * 60,))) is None
    outcome = check_budget(budget_input(payloads=("x" * 60, "y" * 60)))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "BUDGET_EGRESS_BYTES")


@pytest.mark.attack("A9")
def test_unresolved_payload_fails_closed(budget_input: Callable[..., StepInput]) -> None:
    inp = budget_input(payloads=("hello",))
    outcome = check_budget(replace(inp, values={}))
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "BUDGET_EGRESS_BYTES")
    assert outcome.detail == "egress volume exceeds the budget"


@pytest.mark.invariant("I2")
def test_contract_may_tighten_a_read_table_entry_so_it_consumes_effect_budget(
    budget_input: Callable[..., StepInput],
) -> None:
    inp = budget_input(table_effect="read", declared_effect="write", effects_used=2)
    outcome = check_budget(inp)
    assert outcome is not None
    assert (outcome.verdict, outcome.code) == ("BLOCK", "BUDGET_SENDS")
    assert (
        check_budget(budget_input(table_effect="read", declared_effect="read", effects_used=2))
        is None
    )


@pytest.mark.invariant("I2")
def test_budget_without_a_scope_uses_the_table_effect(
    budget_input: Callable[..., StepInput],
) -> None:
    """The monitor never gets here without a scope, but the step must not crash if it did."""
    inp = replace(budget_input(table_effect="write", effects_used=2), scope=None)
    outcome = check_budget(inp)
    assert outcome is not None
    assert outcome.code == "BUDGET_SENDS"
    assert (
        check_budget(replace(inp, session=inp.session.model_copy(update={"effects_used": 0})))
        is None
    )


@pytest.mark.attack("A12")
def test_budget_details_are_constant_text(budget_input: Callable[..., StepInput]) -> None:
    amount = check_budget(budget_input(amounts=("150.00",)))
    sends = check_budget(budget_input(effects_used=2))
    egress = check_budget(budget_input(payloads=("x" * 101,)))
    cumulative_egress = check_budget(budget_input(payloads=("x",), egress_bytes_used=100))
    approvals = check_budget(replace(budget_input(approvals_used=3), prior_escalated=True))
    assert [(o.code, o.detail) if o else None for o in (amount, sends, egress)] == [
        ("BUDGET_AMOUNT", "amount exceeds the budget"),
        ("BUDGET_SENDS", "effect count exceeds the budget"),
        ("BUDGET_EGRESS_BYTES", "egress volume exceeds the budget"),
    ]
    assert cumulative_egress is not None
    assert cumulative_egress.detail == "egress volume exceeds the budget"
    assert approvals is not None
    assert (approvals.code, approvals.detail) == (
        "BUDGET_APPROVALS_EXHAUSTED",
        "approval budget is exhausted",
    )
