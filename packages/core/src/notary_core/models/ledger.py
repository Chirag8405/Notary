"""Ledger of known-good values and human endorsements."""

from typing import Annotated, Literal

from pydantic import Field

from notary_core.models.labels import Integrity, NotaryModel, Origin, ValueRef


class LedgerEntry(NotaryModel):
    entry_id: str
    ledger: str
    key: str
    value: ValueRef


class DiffRow(NotaryModel):
    """One parameter of the proposed call, rendered from its label."""

    param: str
    value_id: str
    origin: Origin
    integrity: Integrity
    preview: str


class DiffCard(NotaryModel):
    rows: tuple[DiffRow, ...]


EndorsementStatus = Literal["pending", "approved", "rejected"]


class Endorsement(NotaryModel):
    endorsement_id: str
    call_id: str
    card: DiffCard
    status: EndorsementStatus
    sequence: Annotated[int, Field(ge=0)]
