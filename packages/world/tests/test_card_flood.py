"""Issue #342: a flood of cards is cut off, whether or not the user answers them.

The budget counts the cards the monitor raised, not only the approvals. With `max_approvals` = 3
the 10th escalation of a session is a BLOCK (`BUDGET_ESCALATIONS_EXHAUSTED`).
"""

import pytest

from notary_world.executor import RunRecord, execute_run
from notary_world.invariants import check_invariants
from notary_world.scenarios import get_scenario
from notary_world.tools import RawToolCall

# Names that are not lookalikes of each other, so only the budget can stop the flood.
WORDS = (
    "apple", "bridge", "crystal", "dolphin", "eagle", "forest",
    "glacier", "harbor", "island", "jungle", "kitchen", "lantern",
)  # fmt: skip


def _flood(count: int, escalation: str) -> RunRecord:
    scenario = get_scenario("contact_phish")
    calls = [
        RawToolCall(
            call_id=f"c{i}",
            tool="add_contact",
            args={"name": word.title(), "email": f"{word}@{word}.example", "iban": ""},
        )
        for i, word in enumerate(WORDS[:count], start=1)
    ]
    return execute_run(
        scenario="flood",
        run_id="flood",
        request=scenario.user_request,
        world=scenario.world,
        contract=scenario.contract,
        ledger=scenario.ledger,
        session=scenario.session,
        calls=calls,
        escalation="approve_all" if escalation == "approve" else "reject",
    )


@pytest.mark.attack("A11")
def test_the_tenth_card_of_a_flood_the_user_rejects_is_a_block() -> None:
    run = _flood(12, "reject")
    verdicts = [c.decision.verdict for c in run.calls]
    assert verdicts == ["ESCALATE"] * 9 + ["BLOCK"] * 3
    last = run.calls[9].decision.reasons[-1]
    assert (last.check, last.code) == ("budget", "BUDGET_ESCALATIONS_EXHAUSTED")
    assert len(run.escalations) == 9
    assert all(result.passed for result in check_invariants(run))


@pytest.mark.attack("A11")
def test_approvals_still_run_out_first_when_the_user_says_yes() -> None:
    run = _flood(12, "approve")
    approved = [e for e in run.escalations if e.resolution == "approved"]
    assert len(approved) == 3
    blocked = [c for c in run.calls if c.decision.verdict == "BLOCK"]
    assert blocked
    codes = {r.code for c in blocked for r in c.decision.reasons if r.outcome == "fail"}
    assert codes == {"BUDGET_APPROVALS_EXHAUSTED"}


@pytest.mark.attack("A11")
def test_a_single_real_card_after_a_few_rejections_still_reaches_the_user() -> None:
    run = _flood(4, "reject")
    assert [c.decision.verdict for c in run.calls] == ["ESCALATE"] * 4
