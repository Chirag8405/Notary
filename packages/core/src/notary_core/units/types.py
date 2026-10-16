from dataclasses import dataclass

from notary_core.models import DecisionUnit


@dataclass(frozen=True, slots=True)
class Canonical:
    unit: DecisionUnit
    value: str  # canonical form; best effort if valid is False
    valid: bool
