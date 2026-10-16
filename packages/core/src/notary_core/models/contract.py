"""Intent contract: what the user authorised, fixed before the agent runs."""

from typing import Annotated, Literal

from pydantic import Field

from notary_core.models.labels import NotaryModel


class LiteralMarker(NotaryModel):
    """Parameter must equal this exact value."""

    kind: Literal["literal"]
    value: str | int | bool


class NamedSourceMarker(NotaryModel):
    """Parameter must come from a named source (e.g. a contact book entry)."""

    kind: Literal["named_source"]
    source: str


class LedgerMarker(NotaryModel):
    """Parameter must resolve to an entry of the named ledger."""

    kind: Literal["ledger"]
    ledger: str


class EndorseMarker(NotaryModel):
    """Parameter may be untrusted but only after explicit human endorsement."""

    kind: Literal["endorse"]


class FreeMarker(NotaryModel):
    """Parameter is unconstrained by the contract."""

    kind: Literal["free"]


Marker = Annotated[
    LiteralMarker | NamedSourceMarker | LedgerMarker | EndorseMarker | FreeMarker,
    Field(discriminator="kind"),
]


class EffectBudget(NotaryModel):
    max_effects: Annotated[int, Field(ge=0)]
    max_spend_cents: Annotated[int, Field(ge=0)]
    max_egress_bytes: Annotated[int, Field(ge=0)]


class ToolScope(NotaryModel):
    tool: str
    params: dict[str, Marker]


class IntentContract(NotaryModel):
    contract_id: str
    user_intent: str
    allowed_tools: tuple[ToolScope, ...]
    budget: EffectBudget
