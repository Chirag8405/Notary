"""WebSocket events: the contract between server and web."""

from typing import Annotated, Literal

from pydantic import Field

from notary_core.models.contract import IntentContract
from notary_core.models.decision import Decision, ToolCallProposal
from notary_core.models.labels import NotaryModel, ValueRef
from notary_core.models.ledger import Endorsement
from notary_core.models.oracle import OracleResult


class EventBase(NotaryModel):
    run_id: str
    seq: Annotated[int, Field(ge=0)]


class RunStarted(EventBase):
    type: Literal["run_started"]
    scenario: str
    contract: IntentContract


class ValueLabeled(EventBase):
    type: Literal["value_labeled"]
    value: ValueRef


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
