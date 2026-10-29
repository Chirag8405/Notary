"""Frozen-contract validators (P0b): reasons, decisions, contracts, commands, attack cases."""

import pytest
from core_builders import budget, contract, decision, reason, scope, sha
from pydantic import TypeAdapter, ValidationError

from notary_core.models import (
    ATTACK_CATEGORY_IDS,
    AttackCase,
    Command,
    Decision,
    EffectBudget,
    Event,
    ExpectedOutcome,
    LedgerEntry,
    LedgerSource,
    SessionState,
    ToolScope,
)
from notary_core.models.decision import CODE_CHECK, StepOutcome


def test_reason_rejects_code_for_wrong_check() -> None:
    with pytest.raises(ValidationError):
        reason("scope", "fail", "BUDGET_AMOUNT")


def test_reason_pass_outcome_requires_pass_code() -> None:
    with pytest.raises(ValidationError):
        reason("origin", "pass", "ORIGIN_UNTRUSTED")


def test_reason_escalate_requires_novel_escalate_code() -> None:
    with pytest.raises(ValidationError):
        reason("corroboration", "escalate", "LEDGER_LOOKALIKE")
    assert reason("corroboration", "escalate", "LEDGER_NOVEL_ESCALATE")


def test_reason_fail_rejects_pass_codes() -> None:
    with pytest.raises(ValidationError):
        reason("scope", "fail", "STEP_PASS")


def test_every_check_has_a_failing_code() -> None:
    from notary_core.models import CHECK_ORDER

    for check in CHECK_ORDER:
        assert any(
            owner == check and code not in {"STEP_PASS", "READ_ONLY_UNGATED", "LEDGER_EXACT_MATCH"}
            for code, owner in CODE_CHECK.items()
        )


def test_decision_allow_rejects_failing_reason() -> None:
    with pytest.raises(ValidationError):
        decision("ALLOW", reason("scope", "fail", "SCOPE_TOOL_NOT_IN_CONTRACT"))


def test_decision_block_requires_failing_reason() -> None:
    with pytest.raises(ValidationError):
        decision("BLOCK", reason("scope", "pass", "STEP_PASS"))


def test_decision_escalate_rejects_fail_reason() -> None:
    with pytest.raises(ValidationError):
        decision(
            "ESCALATE",
            reason("origin", "fail", "ORIGIN_UNTRUSTED"),
            reason("corroboration", "escalate", "LEDGER_NOVEL_ESCALATE"),
        )


def test_decision_rejects_empty_reasons() -> None:
    for verdict in ("ALLOW", "BLOCK", "ESCALATE"):
        with pytest.raises(ValidationError):
            decision(verdict)


def test_decision_reasons_must_follow_check_order() -> None:
    ok = (reason("scope", "pass", "STEP_PASS"), reason("origin", "fail", "ORIGIN_UNTRUSTED"))
    assert decision("BLOCK", *ok)
    with pytest.raises(ValidationError):
        decision("BLOCK", *reversed(ok))


def test_decision_diff_card_only_on_escalate() -> None:
    from notary_core.models import DiffCard

    with pytest.raises(ValidationError):
        Decision(
            verdict="BLOCK",
            reasons=(reason("scope", "fail", "SCOPE_TOOL_NOT_IN_CONTRACT"),),
            diff_card=DiffCard(rows=()),
        )


def test_decision_json_round_trip() -> None:
    d = decision("BLOCK", reason("scope", "fail", "SCOPE_MANIFEST_MISMATCH"))
    assert Decision.model_validate_json(d.model_dump_json()) == d


def test_step_outcome_rules() -> None:
    assert StepOutcome(verdict="BLOCK", code="BUDGET_SENDS", detail="", diff_card=None)
    with pytest.raises(ValidationError):
        StepOutcome(verdict="ALLOW", code="BUDGET_SENDS", detail="", diff_card=None)
    with pytest.raises(ValidationError):
        StepOutcome(verdict="BLOCK", code="STEP_PASS", detail="", diff_card=None)


def test_toolscope_requires_manifest_hash_and_effect() -> None:
    with pytest.raises(ValidationError):
        ToolScope.model_validate({"tool": "t", "params": {}})
    with pytest.raises(ValidationError):
        ToolScope.model_validate(
            {"tool": "t", "params": {}, "manifest_hash": "nope", "effect": "write"}
        )


def test_contract_rejects_duplicate_tool_names() -> None:
    with pytest.raises(ValidationError):
        contract(tools=(scope("a"), scope("a")))


def test_contract_rejects_authorizing_a_non_irreversible_tool() -> None:
    with pytest.raises(ValidationError):
        contract(tools=(scope("a", "write"),), authorized=("a",))
    with pytest.raises(ValidationError):
        contract(tools=(), authorized=("ghost",))
    assert contract(tools=(scope("a", "irreversible"),), authorized=("a",))


def test_egress_hosts_must_be_lowercase_bare_domains() -> None:
    for bad in ("Evil.com", "https://a.com", "a.com/x", "a b.com"):
        with pytest.raises(ValidationError):
            contract(egress=(bad,))
    assert contract(egress=("a.com",))


def test_budget_and_session_fields_are_non_negative() -> None:
    with pytest.raises(ValidationError):
        EffectBudget.model_validate({**budget().model_dump(), "max_approvals": -1})
    with pytest.raises(ValidationError):
        SessionState(
            spent_cents=-1,
            effects_used=0,
            egress_bytes_used=0,
            approvals_used=0,
            escalations_used=0,
        )


def test_contract_json_round_trip() -> None:
    c = contract(
        tools=(scope("pay", "irreversible"),), egress=("acme.example",), authorized=("pay",)
    )
    assert type(c).model_validate_json(c.model_dump_json()) == c


def test_manifest_hash_helper_is_a_sha256() -> None:
    assert len(sha("x")) == 64


def test_attack_case_category_must_match_id() -> None:
    expected = ExpectedOutcome(verdict="BLOCK", deciding_check="scope", code=None)
    with pytest.raises(ValidationError):
        AttackCase(id="A1", category="lookalike", title="t", payload="p", expected=expected)
    assert AttackCase(
        id="A1", category="instruction_override", title="t", payload="p", expected=expected
    )
    assert len(ATTACK_CATEGORY_IDS) == 14


COMMANDS = [
    {"type": "endorsement_decision", "run_id": "r", "endorsement_id": "e", "decision": "approve"},
    {"type": "endorsement_decision", "run_id": "r", "endorsement_id": "e", "decision": "approve",
     "code": "K7Q2M9XA"},
    {"type": "hijacked_tool_call", "run_id": "r", "call_id": "c", "tool": "t", "args": {"a": "b"}},
    {"type": "poison_world", "scenario": "s", "vector": "email", "payload": "p", "task": "t",
     "lanes": ["notary"]},
    {"type": "arena_start", "scenario": "s", "rounds": 3, "lanes": ["notary"], "seed": 1},
]  # fmt: skip


@pytest.mark.parametrize("raw", COMMANDS)
def test_commands_parse_and_round_trip(raw: dict[str, object]) -> None:
    import json

    adapter: TypeAdapter[Command] = TypeAdapter(Command)
    parsed = adapter.validate_json(json.dumps(raw))
    assert json.loads(adapter.dump_json(parsed, exclude_none=True)) == raw


def test_command_rejects_unknown_type_and_extra_fields() -> None:
    adapter: TypeAdapter[Command] = TypeAdapter(Command)
    with pytest.raises(ValidationError):
        adapter.validate_json('{"type":"shutdown"}')
    with pytest.raises(ValidationError):
        adapter.validate_json(
            '{"type":"endorsement_decision","run_id":"r","endorsement_id":"e",'
            '"decision":"approve","extra":1}'
        )
    with pytest.raises(ValidationError):
        adapter.validate_json(
            '{"type":"arena_start","scenario":"s","rounds":0,"lanes":[],"seed":1}'
        )


def test_every_event_carries_run_id_and_lane() -> None:
    from notary_core.models import EventBase

    assert {"run_id", "lane"} <= set(EventBase.model_fields)
    adapter: TypeAdapter[Event] = TypeAdapter(Event)
    with pytest.raises(ValidationError):
        adapter.validate_json('{"type":"run_finished","run_id":"r","seq":0}')


def test_resolved_value_allows_hash_mismatch() -> None:
    from notary_core.models import Label, ResolvedValue, UserOrigin, ValueRef

    label = Label(
        origin=UserOrigin(kind="user"), integrity="trusted", readers=("*",), span_pointer=None
    )
    ref = ValueRef(id="v", label=label, content_hash=sha("real text"))
    value = ResolvedValue(ref=ref, unit=None, text="tampered text")
    assert value.ref.content_hash != sha(value.text)


def test_ledger_source_is_discriminated_and_has_no_tool_result_kind() -> None:
    adapter: TypeAdapter[LedgerSource] = TypeAdapter(LedgerSource)
    assert adapter.validate_python({"kind": "user_authored"}).kind == "user_authored"
    assert adapter.validate_python({"kind": "user_endorsed", "endorsement_id": "e"}).kind == (
        "user_endorsed"
    )
    with pytest.raises(ValidationError):
        adapter.validate_python({"kind": "tool_result"})


def test_ledger_entry_requires_unit_canonical_and_source() -> None:
    with pytest.raises(ValidationError):
        LedgerEntry.model_validate({"entry_id": "e", "ledger": "payees", "key": "k"})
    fields = set(LedgerEntry.model_fields)
    assert {"unit", "canonical", "source"} <= fields


def test_diff_row_has_explicit_nearest_value_and_positions() -> None:
    from notary_core.models import DiffRow, UserOrigin

    row = DiffRow(
        param="payee",
        value_id="v",
        origin=UserOrigin(kind="user"),
        integrity="untrusted",
        preview="DE00X",
        nearest_ledger_value=None,
        differing_positions=(),
    )
    assert row.differing_positions == ()
    with pytest.raises(ValidationError):
        DiffRow.model_validate({"param": "p", "value_id": "v", "preview": "x"})


def test_decide_keeps_the_five_positional_arguments_and_adds_a_keyword_policy() -> None:
    import inspect

    from notary_core.monitor import decide

    params = inspect.signature(decide).parameters
    positional = [n for n, p in params.items() if p.kind is not inspect.Parameter.KEYWORD_ONLY]
    assert positional == ["contract", "proposal", "values", "ledger", "session"]
    assert params["policy"].kind is inspect.Parameter.KEYWORD_ONLY


def test_budget_fields_non_negative() -> None:
    with pytest.raises(ValidationError):
        EffectBudget.model_validate({**budget().model_dump(), "max_effects": -1})


def test_contract_rejects_authorized_irreversible_for_non_irreversible_tool() -> None:
    with pytest.raises(ValidationError):
        contract(tools=(scope("a", "write"),), authorized=("a",))


def test_contract_rejects_authorized_irreversible_for_unknown_tool() -> None:
    with pytest.raises(ValidationError):
        contract(tools=(), authorized=("ghost",))


def test_session_state_non_negative() -> None:
    with pytest.raises(ValidationError):
        SessionState(
            spent_cents=0,
            effects_used=-1,
            egress_bytes_used=0,
            approvals_used=0,
            escalations_used=0,
        )
