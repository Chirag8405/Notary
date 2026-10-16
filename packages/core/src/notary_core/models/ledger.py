"""Ledger of known-good values and human endorsements."""

from typing import Annotated, Literal

from pydantic import Field

from notary_core.models.labels import Integrity, NotaryModel, Origin, ValueRef
from notary_core.models.values import DecisionUnit


class UserAuthoredSource(NotaryModel):
    kind: Literal["user_authored"]


class UserEndorsedSource(NotaryModel):
    kind: Literal["user_endorsed"]
    endorsement_id: str


LedgerSource = Annotated[UserAuthoredSource | UserEndorsedSource, Field(discriminator="kind")]
"""Only user-written or user-endorsed entries exist (I4); there is no tool-result source."""


class LedgerEntry(NotaryModel):
    entry_id: str
    ledger: str
    """Ledger name, e.g. "payees", "contacts"."""
    key: str
    """Human label, e.g. "Acme Utilities"."""
    value: ValueRef
    unit: DecisionUnit
    canonical: str
    """Canonical form of the value in `unit`."""
    source: LedgerSource


class DiffRow(NotaryModel):
    """One parameter of the proposed call, rendered from its label."""

    param: str
    value_id: str
    origin: Origin
    integrity: Integrity
    preview: str
    """The proposed value, canonical form."""
    nearest_ledger_value: str | None
    differing_positions: tuple[int, ...]
    """Indices into `preview` that differ from `nearest_ledger_value`."""


class DiffCard(NotaryModel):
    rows: tuple[DiffRow, ...]


EndorsementStatus = Literal["pending", "approved", "rejected"]


class Endorsement(NotaryModel):
    endorsement_id: str
    call_id: str
    card: DiffCard
    status: EndorsementStatus
    sequence: Annotated[int, Field(ge=0)]
