"""Reference monitor (stub)."""

from collections.abc import Mapping, Sequence

from notary_core.models import Decision, IntentContract, LedgerEntry, ToolCallProposal, ValueRef


def decide(
    contract: IntentContract,
    proposal: ToolCallProposal,
    values: Mapping[str, ValueRef],
    ledger: Sequence[LedgerEntry],
) -> Decision:
    """Decide whether a proposed tool call may run.

    Checks run in this fixed order and the resulting `Decision.reasons` list
    follows the same order:

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
