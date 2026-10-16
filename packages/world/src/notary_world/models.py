"""Typed shape of the JSON fixtures. Fixtures are validated against these models on load."""

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from notary_core.models import AttackCase, ExpectedOutcome, Lane, NotaryModel, Sha256Hex


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


class CassetteEntry(NotaryModel):
    key: Sha256Hex
    """`cassette_key(lane, prompt)`: sha256 of the lane and the exact prompt."""
    response: CassetteTurn


class Cassette(NotaryModel):
    """Recorded LLM responses replayed instead of calling a model. One cassette per lane."""

    name: str
    model: str
    lane: Lane
    entries: tuple[CassetteEntry, ...]


class WorldOverlay(NotaryModel):
    """Poisoned content added on top of the seeded world for one attack."""

    mail: tuple[Email, ...]
    files: tuple[WorldFile, ...]


class ScriptedCall(NotaryModel):
    """A tool call the (hijacked or scripted) agent proposes, with the verdict it must get."""

    call_id: str
    tool: str
    args: dict[str, str]
    """Raw argument text per parameter; the Gateway labels it."""
    expected: ExpectedOutcome


class AttackFixture(NotaryModel):
    """One attack of the library (A1-A14): the frozen fixture format."""

    case: AttackCase
    user_request: str
    overlay: WorldOverlay
    scripted: tuple[ScriptedCall, ...]
    attacker_goal_id: str
    user_goal_id: str
    covers: tuple[str, ...]
    """I/A ids this fixture exercises (always includes `case.id`)."""
    deferred_to: Literal["P3a"] | None
    """Set when the monitor cannot decide it (A13: Output Guard); excluded from CP1."""

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if not self.scripted:
            raise ValueError("a fixture needs at least one scripted call")
        ids = [call.call_id for call in self.scripted]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate call_id in scripted calls")
        if self.scripted[-1].expected != self.case.expected:
            raise ValueError("the last scripted call must carry the case's expected outcome")
        if self.case.id not in self.covers:
            raise ValueError("covers must include the attack id")
        return self
