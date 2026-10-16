"""Provenance primitives: origins, integrity, labels and value references."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

HASH_PATTERN = r"^[0-9a-f]{64}$"
"""Lowercase hex SHA-256 digest."""

Sha256Hex = Annotated[str, Field(pattern=HASH_PATTERN)]


class NotaryModel(BaseModel):
    """Base for every NOTARY model: immutable, strict, no unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class UserOrigin(NotaryModel):
    kind: Literal["user"]


class ToolOrigin(NotaryModel):
    kind: Literal["tool"]
    name: str


class EmailOrigin(NotaryModel):
    kind: Literal["email"]


class FileOrigin(NotaryModel):
    kind: Literal["file"]


class WebOrigin(NotaryModel):
    kind: Literal["web"]


class LedgerOrigin(NotaryModel):
    kind: Literal["ledger"]


class LlmOrigin(NotaryModel):
    kind: Literal["llm"]


Origin = Annotated[
    UserOrigin | ToolOrigin | EmailOrigin | FileOrigin | WebOrigin | LedgerOrigin | LlmOrigin,
    Field(discriminator="kind"),
]
"""Where a value came from: user | tool:<name> | email | file | web | ledger | llm."""

Integrity = Literal["trusted", "untrusted", "endorsed"]

Lane = Literal["undefended", "classifier", "notary"]
"""Defense configuration of a run: no hooks, classifier pre-filter, or Gateway + monitor."""


class SpanPointer(NotaryModel):
    """Points at the span of a source value that a derived value was taken from."""

    source_value_id: str
    start: Annotated[int, Field(ge=0)]
    end: Annotated[int, Field(ge=0)]


class Label(NotaryModel):
    origin: Origin
    integrity: Integrity
    readers: tuple[str, ...]
    span_pointer: SpanPointer | None


class ValueRef(NotaryModel):
    """A labeled handle to a value. Raw content never travels through the monitor."""

    id: str
    label: Label
    content_hash: Sha256Hex
