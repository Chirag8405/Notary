"""Reference monitor (stub)."""

from collections.abc import Mapping, Sequence
from typing import Protocol

from notary_core.models import (
    Decision,
    IntentContract,
    LedgerEntry,
    Reason,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
)
from notary_core.pipeline import StepInput, run_steps
from notary_core.policy.sensitive_params import DEFAULT_POLICY, PolicyTable, effective_effect
from notary_core.steps import STEPS
from notary_core.steps.scope import check_scope


class Monitor(Protocol):
    """The frozen `decide()` signature; `decide` and test doubles (`FakeMonitor`) satisfy it."""

    def __call__(
        self,
        contract: IntentContract,
        proposal: ToolCallProposal,
        values: Mapping[str, ResolvedValue],
        ledger: Sequence[LedgerEntry],
        session: SessionState,
    ) -> Decision: ...


def decide(
    contract: IntentContract,
    proposal: ToolCallProposal,
    values: Mapping[str, ResolvedValue],
    ledger: Sequence[LedgerEntry],
    session: SessionState,
    *,
    policy: PolicyTable = DEFAULT_POLICY,
) -> Decision:
    """Decide whether a proposed tool call may run.

    `values` is keyed by `ValueRef.id` and holds the text of every argument (the Value Store
    resolves it). `session` carries the running budget state; the caller owns and updates it.
    `policy` is the sensitive-parameter table; tests inject their own, callers use the default.

    Checks run in this fixed order and the resulting `Decision.reasons` list
    follows the same order (evaluation stops at the first BLOCK):

    1. scope            - is the tool and each parameter within the contract?
    2. irreversibility  - is the effect irreversible (needs stronger evidence)?
    3. origin           - do argument labels satisfy the per-parameter markers?
    4. corroboration    - is an untrusted-origin value corroborated by the ledger?
    5. confidentiality  - would data flow to a reader outside the label's readers (egress)?
    6. budget           - does the call fit the remaining effect budget?

    Any failing check yields BLOCK; any escalating check (and none failing)
    yields ESCALATE; otherwise ALLOW.

    A tool whose effective effect is `read` has no side effect and no outbound channel, so after
    step 1 passes it is allowed at once with a single `READ_ONLY_UNGATED` reason.

    Steps 3-6 are still placeholders that raise `NotImplementedError`; once all steps land this
    function must never raise for structurally valid input (it fails closed with BLOCK).
    """
    scope = next((t for t in contract.allowed_tools if t.tool == proposal.tool), None)
    inp = StepInput(
        contract=contract,
        proposal=proposal,
        values=values,
        ledger=ledger,
        session=session,
        scope=scope,
        policy=policy,
        prior_escalated=False,
    )
    # Step 1 runs again inside `run_steps` below; it is pure and cheap, and this keeps the
    # read-only bypass out of the runner.
    if (
        scope is not None
        and check_scope(inp) is None
        and effective_effect(policy, proposal.tool, scope.effect) == "read"
    ):
        reason = Reason(
            check="scope",
            outcome="pass",
            code="READ_ONLY_UNGATED",
            detail="read-only tool; later checks do not apply",
        )
        return Decision(verdict="ALLOW", reasons=(reason,), diff_card=None)
    return run_steps(STEPS, inp)
