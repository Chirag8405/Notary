"""Reference monitor (stub)."""

from collections.abc import Mapping, Sequence
from typing import Protocol

from notary_core.models import (
    Decision,
    IntentContract,
    LedgerEntry,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
)


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
) -> Decision:
    """Decide whether a proposed tool call may run.

    `values` is keyed by `ValueRef.id` and holds the text of every argument (the Value Store
    resolves it). `session` carries the running budget state; the caller owns and updates it.

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

    Not implemented yet.
    """
    raise NotImplementedError
