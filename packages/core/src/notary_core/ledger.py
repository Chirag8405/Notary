"""Trusted ledger: append-only writes that only user authority can make (I4, A9).

Only trusted code (the user's typed-request handling and the Endorsement
Service) may construct UserAuthoredAuthority or UserEndorsedAuthority. Core
checks the consistency of the authority with the entry, not whether an
endorsement exists; that belongs to the Endorsement Service.
"""

from collections.abc import Sequence
from typing import Annotated, Literal

from pydantic import Field

from notary_core.models import (
    DecisionUnit,
    LedgerEntry,
    NotaryModel,
    UserAuthoredSource,
    UserEndorsedSource,
)
from notary_core.units import canonicalize

Ledger = tuple[LedgerEntry, ...]

ERR_AUTHORITY = "ledger writes require user authority"
ERR_SOURCE_MISMATCH = "entry source does not match write authority"
ERR_NOT_CANONICAL = "entry is not in canonical form"
ERR_ENTRY_ID_USED = "entry_id already used"


class UserAuthoredAuthority(NotaryModel):
    kind: Literal["user_authored"]


class UserEndorsedAuthority(NotaryModel):
    kind: Literal["user_endorsed"]
    endorsement_id: str


class ToolResultAuthority(NotaryModel):
    kind: Literal["tool_result"]
    tool: str


class LlmAuthority(NotaryModel):
    kind: Literal["llm"]


WriteAuthority = Annotated[
    UserAuthoredAuthority | UserEndorsedAuthority | ToolResultAuthority | LlmAuthority,
    Field(discriminator="kind"),
]


class LedgerClosureError(Exception):
    """A write was refused; the message is one of the fixed ERR_* constants."""


def entries_for(
    ledger: Sequence[LedgerEntry], unit: DecisionUnit, ledger_name: str | None = None
) -> Ledger:
    """Entries of `unit` (and of `ledger_name` when given), in ledger order."""
    return tuple(
        e for e in ledger if e.unit == unit and (ledger_name is None or e.ledger == ledger_name)
    )


def find_exact(
    ledger: Sequence[LedgerEntry],
    unit: DecisionUnit,
    canonical: str,
    ledger_name: str | None = None,
) -> LedgerEntry | None:
    """First entry whose canonical form equals `canonical`.

    The caller must pass an already-canonical string: nothing is canonicalized or
    folded here, and there is no lookalike matching (see notary_core.lookalike).
    """
    for e in entries_for(ledger, unit, ledger_name):
        if e.canonical == canonical:
            return e
    return None


def _source_matches(
    entry: LedgerEntry, authority: UserAuthoredAuthority | UserEndorsedAuthority
) -> bool:
    source = entry.source
    if isinstance(authority, UserAuthoredAuthority):
        return isinstance(source, UserAuthoredSource)
    if not isinstance(source, UserEndorsedSource):
        return False
    # Empty ids never match, and ids are compared as plain strings.
    return authority.endorsement_id != "" and authority.endorsement_id == source.endorsement_id


def with_entry(
    ledger: Sequence[LedgerEntry], entry: LedgerEntry, authority: WriteAuthority
) -> Ledger:
    """Append `entry` to the ledger if user authority backs it; never mutates `ledger`.

    Rules run in a fixed order, which is a security property: authority first (an
    allowlist, so anything unknown fails closed, even for an entry that already
    exists), then source consistency, canonical form, entry_id reuse and finally
    the trust-on-first-use duplicate check. A write of an existing
    (ledger, unit, canonical) returns the ledger unchanged: the first write wins,
    even if the later entry has different metadata such as another entry_id.
    """
    if not isinstance(authority, (UserAuthoredAuthority, UserEndorsedAuthority)):
        raise LedgerClosureError(ERR_AUTHORITY)
    if not _source_matches(entry, authority):
        raise LedgerClosureError(ERR_SOURCE_MISMATCH)
    # Only the canonical value is compared; `.valid` is informational.
    if canonicalize(entry.unit, entry.canonical).value != entry.canonical:
        raise LedgerClosureError(ERR_NOT_CANONICAL)
    if any(e.entry_id == entry.entry_id and e != entry for e in ledger):
        raise LedgerClosureError(ERR_ENTRY_ID_USED)
    if any(
        e.ledger == entry.ledger and e.unit == entry.unit and e.canonical == entry.canonical
        for e in ledger
    ):
        return tuple(ledger)
    return (*ledger, entry)
