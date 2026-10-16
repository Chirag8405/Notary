"""Pure approval logic of the Endorsement Service: ledger entries from an approved diff card.

The monitor builds the card from labels (step 4); this module turns an APPROVED card into ledger
entries, writes them through the closed ledger path (user authority only, all rows or none),
reports the remaining approval budget and renders a card as plain text built only from labels.
Pure: no I/O, clock or randomness.
"""

from collections.abc import Mapping, Sequence

from notary_core.ledger import LedgerClosureError, UserEndorsedAuthority, with_entry
from notary_core.models import (
    DecisionUnit,
    DiffCard,
    IntentContract,
    LedgerEntry,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
    ToolOrigin,
    UserEndorsedSource,
)

ENDORSED_LEDGER: str = "endorsed"
"""Where approved values go. Step 4 searches every ledger of the unit for an `endorse` marker but
only the named ledger for a `ledger` marker, so an endorsement corroborates `endorse` parameters,
never a `ledger(payees)` parameter."""

ERR_BAD_APPROVAL_ROW: str = "approval row does not match the proposal"


def approval_entries(
    endorsement_id: str,
    card: DiffCard,
    proposal: ToolCallProposal,
    values: Mapping[str, ResolvedValue],
    units: Mapping[str, DecisionUnit | None],
) -> tuple[LedgerEntry, ...] | str:
    """One ledger entry per card row, or `ERR_BAD_APPROVAL_ROW`: all rows or none.

    A row must describe the very value the proposal carries for that parameter: the parameter must
    be in the proposal, the row's `value_id` must be that argument's id, and the value must be in
    the store. The entry's unit is the parameter's unit (`identifier` when unknown).
    """
    entries: list[LedgerEntry] = []
    for row in card.rows:
        ref = proposal.args.get(row.param)
        if ref is None or ref.id != row.value_id:
            return ERR_BAD_APPROVAL_ROW
        value = values.get(ref.id)
        if value is None:
            return ERR_BAD_APPROVAL_ROW
        entries.append(
            LedgerEntry(
                entry_id=f"led-{endorsement_id}-{row.param}",
                ledger=ENDORSED_LEDGER,
                key=f"{row.param}: {row.preview}",
                value=value.ref,
                unit=units.get(row.param) or "identifier",
                canonical=row.preview,
                source=UserEndorsedSource(kind="user_endorsed", endorsement_id=endorsement_id),
            )
        )
    return tuple(entries)


def apply_approval(
    ledger: Sequence[LedgerEntry], entries: Sequence[LedgerEntry], endorsement_id: str
) -> tuple[LedgerEntry, ...] | str:
    """The ledger after writing every entry with user-endorsed authority, or the refusal reason.

    If any write is refused the input ledger is untouched and the message of the refusal is
    returned. Writing the same entries twice changes nothing (the first write wins).
    """
    authority = UserEndorsedAuthority(kind="user_endorsed", endorsement_id=endorsement_id)
    updated = tuple(ledger)
    try:
        for entry in entries:
            updated = tuple(with_entry(updated, entry, authority))
    except LedgerClosureError as error:
        return str(error)
    return updated


def remaining_approvals(contract: IntentContract, session: SessionState) -> int:
    """Approvals left in the session budget (step 6 turns an ESCALATE into a BLOCK at zero)."""
    return max(contract.budget.max_approvals - session.approvals_used, 0)


def render_card(card: DiffCard) -> str:
    """The card as text, from labels only: one line per row, no attacker prose added or removed."""
    lines: list[str] = []
    for row in card.rows:
        origin = (
            f"tool:{row.origin.name}" if isinstance(row.origin, ToolOrigin) else row.origin.kind
        )
        line = f"{row.param}: {row.preview} [{origin}, {row.integrity}]"
        if row.nearest_ledger_value is not None:
            line += f" nearest known: {row.nearest_ledger_value}"
            if row.differing_positions:
                line += f" differs at {', '.join(str(i) for i in row.differing_positions)}"
        lines.append(line)
    return "\n".join(lines)
