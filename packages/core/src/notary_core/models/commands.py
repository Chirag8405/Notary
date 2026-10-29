"""Client -> server command messages (the other half of the server/web contract)."""

from typing import Annotated, Literal, cast

from pydantic import ConfigDict, Field
from pydantic.json_schema import JsonSchemaValue

from notary_core.models.labels import Lane, NotaryModel

Vector = Literal["email", "file", "web", "calendar", "slack", "tool_description"]


def _optional_without_default(schema: JsonSchemaValue) -> None:
    """Leave `code` out of the schema's defaults, so it is an optional key and not one that every
    parsed command gains as `null` (the generated Zod would otherwise add it to each command)."""
    properties = cast("dict[str, dict[str, object]]", schema.get("properties", {}))
    properties.get("code", {}).pop("default", None)


class EndorsementDecisionCommand(NotaryModel):
    model_config = ConfigDict(json_schema_extra=_optional_without_default)

    type: Literal["endorsement_decision"]
    run_id: str
    endorsement_id: str
    decision: Literal["approve", "reject", "use_nearest"]
    """`use_nearest` rejects the proposed value and proposes the call again with the nearest known
    ledger value of every parameter on the card; nothing is written to the ledger."""
    code: str | None = Field(default=None, max_length=64)
    """MCP proxy runs only: the one-time approval code the proxy printed for this card, typed by
    the user. The server forwards it to the proxy and never stores or logs it."""


class HijackedToolCallCommand(NotaryModel):
    """Hijacked Mode: a judge submits a raw tool call; no LLM is involved."""

    type: Literal["hijacked_tool_call"]
    run_id: str
    call_id: str
    tool: str
    args: dict[str, str]
    """Raw argument text per parameter; the Gateway labels it."""


class PoisonWorldCommand(NotaryModel):
    """Poison-the-world: choose vector, payload and task, then run on the chosen lanes."""

    type: Literal["poison_world"]
    scenario: str
    vector: Vector
    payload: str
    task: str
    lanes: tuple[Lane, ...]


class ArenaStartCommand(NotaryModel):
    """Attacker arena: an LLM attacker iterates `rounds` per lane."""

    type: Literal["arena_start"]
    scenario: str
    rounds: Annotated[int, Field(ge=1, le=100)]
    lanes: tuple[Lane, ...]
    seed: Annotated[int, Field(ge=0)]


Command = Annotated[
    EndorsementDecisionCommand | HijackedToolCallCommand | PoisonWorldCommand | ArenaStartCommand,
    Field(discriminator="type"),
]
