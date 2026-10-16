"""Typed shape of the JSON fixtures. Fixtures are validated against these models on load."""

from typing import Annotated, Literal

from pydantic import Field

from notary_core.models import NotaryModel


class Email(NotaryModel):
    id: str
    sender: str
    subject: str
    body: str
    trusted: bool


class Contact(NotaryModel):
    name: str
    iban: str


class Account(NotaryModel):
    iban: str
    balance_cents: Annotated[int, Field(ge=0)]


class BankState(NotaryModel):
    accounts: tuple[Account, ...]
    contacts: tuple[Contact, ...]


class WorldFile(NotaryModel):
    path: str
    content: str
    secret: bool


class World(NotaryModel):
    seed: int
    mail: tuple[Email, ...]
    bank: BankState
    files: tuple[WorldFile, ...]


class CassetteToolCall(NotaryModel):
    tool: str
    args: dict[str, str]


class CassetteTurn(NotaryModel):
    role: Literal["user", "assistant", "tool"]
    content: str
    tool_calls: tuple[CassetteToolCall, ...]


class Cassette(NotaryModel):
    """A recorded LLM conversation, replayed instead of calling a model."""

    name: str
    model: str
    turns: tuple[CassetteTurn, ...]
