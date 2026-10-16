"""Pure step runner: executes monitor steps in `CHECK_ORDER` and aggregates the verdict."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from itertools import pairwise

from notary_core.models import (
    CHECK_ORDER,
    CheckName,
    Decision,
    DiffCard,
    IntentContract,
    LedgerEntry,
    Reason,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
    ToolScope,
)
from notary_core.models.decision import StepOutcome

# TODO(#52): replace with `from notary_core.policy.sensitive_params import PolicyTable` once the
# policy machinery lands. The runner never looks inside the table, so `object` values suffice.
PolicyTable = Mapping[str, object]


@dataclass(frozen=True, slots=True)
class StepInput:
    """Everything a step may read. Internal to the monitor: never serialized."""

    contract: IntentContract
    proposal: ToolCallProposal
    values: Mapping[str, ResolvedValue]
    ledger: Sequence[LedgerEntry]
    session: SessionState
    scope: ToolScope | None
    """The `ToolScope` for `proposal.tool`, or None if the tool is not in the contract."""
    policy: PolicyTable
    prior_escalated: bool
    """True if an earlier step already returned ESCALATE (used by the budget step)."""


Step = Callable[[StepInput], StepOutcome | None]
"""A monitor step. None = pass."""


def _validate_order(steps: Sequence[tuple[CheckName, Step]]) -> None:
    if not steps:
        raise ValueError("run_steps needs at least one step")
    positions = [CHECK_ORDER.index(name) for name, _ in steps]
    if any(a >= b for a, b in pairwise(positions)):
        raise ValueError("steps must follow CHECK_ORDER strictly, without repeats")


def run_steps(steps: Sequence[tuple[CheckName, Step]], inp: StepInput) -> Decision:
    """Run `steps` in order and build the `Decision`.

    BLOCK short-circuits; ESCALATE does not (later steps still run, seeing
    `prior_escalated=True`). Raises `ValueError` if the steps are empty or out of order.
    """
    _validate_order(steps)

    reasons: list[Reason] = []
    cards: list[DiffCard] = []
    for name, step in steps:
        outcome = step(inp)
        if outcome is None:
            reasons.append(Reason(check=name, outcome="pass", code="STEP_PASS", detail=""))
            continue
        if outcome.verdict == "ALLOW":
            reasons.append(
                Reason(check=name, outcome="pass", code=outcome.code, detail=outcome.detail)
            )
        elif outcome.verdict == "ESCALATE":
            reasons.append(
                Reason(check=name, outcome="escalate", code=outcome.code, detail=outcome.detail)
            )
            if outcome.diff_card is not None:
                cards.append(outcome.diff_card)
            inp = replace(inp, prior_escalated=True)
        else:
            reasons.append(
                Reason(check=name, outcome="fail", code=outcome.code, detail=outcome.detail)
            )
            return Decision(verdict="BLOCK", reasons=tuple(reasons), diff_card=None)

    if any(r.outcome == "escalate" for r in reasons):
        card = DiffCard(rows=tuple(row for c in cards for row in c.rows)) if cards else None
        return Decision(verdict="ESCALATE", reasons=tuple(reasons), diff_card=card)
    return Decision(verdict="ALLOW", reasons=tuple(reasons), diff_card=None)
