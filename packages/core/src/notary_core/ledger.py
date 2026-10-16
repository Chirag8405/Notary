"""Trusted ledger: append-only writes that only user authority can make (I4, A9).

Only trusted code (the user's typed-request handling and the Endorsement
Service) may construct UserAuthoredAuthority or UserEndorsedAuthority. Core
checks the consistency of the authority with the entry, not whether an
endorsement exists; that belongs to the Endorsement Service.
"""

from typing import Annotated, Literal

from pydantic import Field

from notary_core.models import LedgerEntry, NotaryModel

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
