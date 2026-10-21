"""Running budget state of a session, supplied by the caller to the monitor."""

from typing import Annotated

from pydantic import Field

from notary_core.models.labels import NotaryModel


class SessionState(NotaryModel):
    spent_cents: Annotated[int, Field(ge=0)]
    effects_used: Annotated[int, Field(ge=0)]
    egress_bytes_used: Annotated[int, Field(ge=0)]
    approvals_used: Annotated[int, Field(ge=0)]
    escalations_used: Annotated[int, Field(ge=0)]
    """Cards raised so far, whatever became of them (approved, rejected, timed out). Bounds a card
    flood: see `MAX_ESCALATIONS_PER_APPROVAL` in the budget step."""
