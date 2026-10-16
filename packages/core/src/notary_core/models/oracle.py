"""World-state oracle: invariants I1-I6."""

from typing import Literal

from notary_core.models.labels import NotaryModel

InvariantId = Literal["I1", "I2", "I3", "I4", "I5", "I6"]


class InvariantResult(NotaryModel):
    id: InvariantId
    passed: bool
    detail: str


class OracleResult(NotaryModel):
    invariants: tuple[InvariantResult, ...]
