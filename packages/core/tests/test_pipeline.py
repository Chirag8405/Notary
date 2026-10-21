"""Tests for the pipeline runner, using fake steps."""

import pytest
from core_builders import contract, scope, sha
from hypothesis import given
from hypothesis import strategies as st

from notary_core.models import (
    CHECK_ORDER,
    CheckName,
    DiffCard,
    DiffRow,
    ReasonCode,
    SessionState,
    ToolCallProposal,
)
from notary_core.models.decision import StepOutcome
from notary_core.pipeline import Step, StepInput, run_steps
from notary_core.policy.sensitive_params import DEFAULT_POLICY


def make_input() -> StepInput:
    tool = scope("pay")
    return StepInput(
        contract=contract((tool,)),
        proposal=ToolCallProposal(call_id="c1", tool="pay", manifest_hash=sha("pay"), args={}),
        values={},
        ledger=(),
        session=SessionState(
            spent_cents=0, effects_used=0, egress_bytes_used=0, approvals_used=0, escalations_used=0
        ),
        scope=tool,
        policy=DEFAULT_POLICY,
        prior_escalated=False,
    )


def outcome(verdict: str, code: ReasonCode, card: DiffCard | None = None) -> StepOutcome:
    return StepOutcome.model_validate(
        {"verdict": verdict, "code": code, "detail": "", "diff_card": card}
    )


def card(param: str) -> DiffCard:
    row = DiffRow.model_validate(
        {
            "param": param,
            "value_id": "v1",
            "origin": {"kind": "email"},
            "integrity": "untrusted",
            "preview": "x",
            "nearest_ledger_value": None,
            "differing_positions": (),
        }
    )
    return DiffCard(rows=(row,))


class Fake:
    """A step that returns a fixed outcome and records how often it was called."""

    def __init__(self, result: StepOutcome | None = None) -> None:
        self.result = result
        self.calls = 0
        self.seen_prior_escalated: bool | None = None

    def __call__(self, inp: StepInput) -> StepOutcome | None:
        self.calls += 1
        self.seen_prior_escalated = inp.prior_escalated
        return self.result


def pipeline(fakes: dict[CheckName, Fake]) -> list[tuple[CheckName, Step]]:
    return [(name, fakes.get(name, Fake())) for name in CHECK_ORDER]


def six_fakes(overrides: dict[CheckName, Fake] | None = None) -> dict[CheckName, Fake]:
    fakes: dict[CheckName, Fake] = {name: Fake() for name in CHECK_ORDER}
    fakes.update(overrides or {})
    return fakes


@pytest.mark.invariant("I6")
def test_all_pass_gives_allow() -> None:
    decision = run_steps(pipeline(six_fakes()), make_input())
    assert decision.verdict == "ALLOW"
    assert [r.check for r in decision.reasons] == list(CHECK_ORDER)
    assert all(r.code == "STEP_PASS" and r.outcome == "pass" for r in decision.reasons)


@pytest.mark.invariant("I6")
def test_block_short_circuits() -> None:
    fakes = six_fakes({"origin": Fake(outcome("BLOCK", "ORIGIN_UNTRUSTED"))})
    decision = run_steps(pipeline(fakes), make_input())
    assert decision.verdict == "BLOCK"
    assert [r.check for r in decision.reasons] == ["scope", "irreversibility", "origin"]
    assert [fakes[n].calls for n in CHECK_ORDER] == [1, 1, 1, 0, 0, 0]


@pytest.mark.invariant("I6")
def test_escalate_does_not_stop_pipeline() -> None:
    fakes = six_fakes(
        {"corroboration": Fake(outcome("ESCALATE", "LEDGER_NOVEL_ESCALATE", card("to")))}
    )
    decision = run_steps(pipeline(fakes), make_input())
    assert decision.verdict == "ESCALATE"
    assert len(decision.reasons) == 6
    assert fakes["confidentiality"].calls == 1
    assert fakes["budget"].calls == 1


@pytest.mark.invariant("I6")
def test_block_beats_escalate() -> None:
    fakes = six_fakes(
        {
            "corroboration": Fake(outcome("ESCALATE", "LEDGER_NOVEL_ESCALATE", card("to"))),
            "confidentiality": Fake(outcome("BLOCK", "CONF_READER_VIOLATION")),
        }
    )
    decision = run_steps(pipeline(fakes), make_input())
    assert decision.verdict == "BLOCK"
    assert decision.diff_card is None
    assert fakes["budget"].calls == 0


@pytest.mark.invariant("I6")
def test_prior_escalated_flag_set_for_later_steps() -> None:
    fakes = six_fakes(
        {"corroboration": Fake(outcome("ESCALATE", "LEDGER_NOVEL_ESCALATE", card("to")))}
    )
    run_steps(pipeline(fakes), make_input())
    assert fakes["scope"].seen_prior_escalated is False
    assert fakes["corroboration"].seen_prior_escalated is False
    assert fakes["budget"].seen_prior_escalated is True


def test_diff_card_only_when_escalate() -> None:
    blocked = run_steps(
        pipeline(six_fakes({"scope": Fake(outcome("BLOCK", "SCOPE_TOOL_NOT_IN_CONTRACT"))})),
        make_input(),
    )
    allowed = run_steps(pipeline(six_fakes()), make_input())
    assert blocked.diff_card is None
    assert allowed.diff_card is None


def test_escalate_card_is_passed_through() -> None:
    fakes = six_fakes(
        {"corroboration": Fake(outcome("ESCALATE", "LEDGER_NOVEL_ESCALATE", card("a")))}
    )
    decision = run_steps(pipeline(fakes), make_input())
    assert decision.diff_card == card("a")


def test_allow_outcome_becomes_pass_reason_with_its_code() -> None:
    fakes = six_fakes({"corroboration": Fake(outcome("ALLOW", "LEDGER_EXACT_MATCH"))})
    decision = run_steps(pipeline(fakes), make_input())
    assert decision.verdict == "ALLOW"
    reason = decision.reasons[3]
    assert (reason.check, reason.outcome, reason.code) == (
        "corroboration",
        "pass",
        "LEDGER_EXACT_MATCH",
    )
    assert fakes["budget"].calls == 1


def test_steps_out_of_order_rejected() -> None:
    steps: list[tuple[CheckName, Step]] = [("origin", Fake()), ("scope", Fake())]
    with pytest.raises(ValueError, match="CHECK_ORDER"):
        run_steps(steps, make_input())


def test_duplicate_check_rejected() -> None:
    steps: list[tuple[CheckName, Step]] = [("scope", Fake()), ("scope", Fake())]
    with pytest.raises(ValueError, match="CHECK_ORDER"):
        run_steps(steps, make_input())


def test_empty_steps_rejected() -> None:
    with pytest.raises(ValueError, match="at least one"):
        run_steps([], make_input())


@pytest.mark.invariant("I6")
def test_run_steps_is_deterministic() -> None:
    def run() -> str:
        fakes = six_fakes(
            {"corroboration": Fake(outcome("ESCALATE", "LEDGER_NOVEL_ESCALATE", card("to")))}
        )
        return run_steps(pipeline(fakes), make_input()).model_dump_json()

    assert run() == run()


@pytest.mark.invariant("I6")
def test_run_steps_does_not_mutate_inputs() -> None:
    inp = make_input()
    before = (
        make_input()
    )  # equal copy; DEFAULT_POLICY is a MappingProxyType and cannot be deep-copied
    run_steps(pipeline(six_fakes()), inp)
    assert inp == before


@pytest.mark.invariant("I6")
@given(st.sets(st.sampled_from(CHECK_ORDER)))
def test_any_ordered_subset_of_passing_steps_is_allow(names: set[CheckName]) -> None:
    ordered: list[CheckName] = [n for n in CHECK_ORDER if n in names]
    if not ordered:
        return
    steps: list[tuple[CheckName, Step]] = [(n, Fake()) for n in ordered]
    decision = run_steps(steps, make_input())
    assert decision.verdict == "ALLOW"
    assert [r.check for r in decision.reasons] == ordered
