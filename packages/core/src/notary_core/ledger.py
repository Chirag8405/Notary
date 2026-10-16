"""Trusted ledger: append-only writes that only user authority can make (I4, A9).

Only trusted code (the user's typed-request handling and the Endorsement
Service) may construct UserAuthoredAuthority or UserEndorsedAuthority. Core
checks the consistency of the authority with the entry, not whether an
endorsement exists; that belongs to the Endorsement Service.
"""

from collections.abc import Sequence
from typing import Annotated, Literal

from pydantic import Field

from notary_core.models import DecisionUnit, LedgerEntry, NotaryModel

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
