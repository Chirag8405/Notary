"""WebSocket events: the contract between server and web."""

from typing import Annotated, Literal

from pydantic import Field

from notary_core.models.contract import IntentContract
from notary_core.models.decision import Decision, ToolCallProposal
from notary_core.models.labels import Lane, NotaryModel, ValueRef
from notary_core.models.ledger import Endorsement
from notary_core.models.oracle import OracleResult
from notary_core.models.values import DecisionUnit


class EventBase(NotaryModel):
    run_id: str
    lane: Lane
    seq: Annotated[int, Field(ge=0)]


class RunStarted(EventBase):
    type: Literal["run_started"]
    scenario: str
    contract: IntentContract
    classifier: str | None
    """Classifier name on the classifier lane (label it a stand-in if it is); None otherwise."""


class ValueLabeled(EventBase):
    type: Literal["value_labeled"]
    value: ValueRef
    unit: DecisionUnit | None
    preview: str
    """Short text excerpt for the UI (the ValueRef itself only carries a hash)."""


class CallProposed(EventBase):
    type: Literal["call_proposed"]
    proposal: ToolCallProposal


class DecisionMade(EventBase):
    type: Literal["decision_made"]
    call_id: str
    decision: Decision


class EndorsementRequested(EventBase):
    type: Literal["endorsement_requested"]
    endorsement: Endorsement


class EffectExecuted(EventBase):
    type: Literal["effect_executed"]
    call_id: str
    tool: str
    summary: str


class OracleUpdated(EventBase):
    type: Literal["oracle_updated"]
    result: OracleResult


class RunFinished(EventBase):
    type: Literal["run_finished"]
    outcome: Literal["completed", "blocked", "error"]
    summary: str


Event = Annotated[
    RunStarted
    | ValueLabeled
    | CallProposed
    | DecisionMade
    | EndorsementRequested
    | EffectExecuted
    | OracleUpdated
    | RunFinished,
    Field(discriminator="type"),
]
