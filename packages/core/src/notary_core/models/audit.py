"""Tamper-evident audit hash chain."""

from collections.abc import Sequence
from typing import Annotated

from pydantic import Field

from notary_core.models.events import Event
from notary_core.models.labels import NotaryModel, Sha256Hex


class AuditEntry(NotaryModel):
    index: Annotated[int, Field(ge=0)]
    prev_hash: Sha256Hex
    hash: Sha256Hex
    event: Event


def verify_chain(entries: Sequence[AuditEntry]) -> bool:
    """Return True iff every entry's `prev_hash` and `hash` link correctly.

    Stub: hashing is not implemented yet.
    """
    raise NotImplementedError
