"""World-state oracle: invariants I1-I6 and the two goal lights."""

from typing import Literal

from notary_core.models.labels import NotaryModel

InvariantId = Literal["I1", "I2", "I3", "I4", "I5", "I6"]


class InvariantResult(NotaryModel):
    id: InvariantId
    passed: bool
    detail: str


class OracleResult(NotaryModel):
    invariants: tuple[InvariantResult, ...]
    attacker_goal_reached: bool
    user_goal_achieved: bool
