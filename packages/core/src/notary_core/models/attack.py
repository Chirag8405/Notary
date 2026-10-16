"""Attack library entries (A1-A14)."""

from typing import Literal

from notary_core.models.decision import CheckName, Verdict
from notary_core.models.labels import NotaryModel

AttackId = Literal[
    "A1", "A2", "A3", "A4", "A5", "A6", "A7",
    "A8", "A9", "A10", "A11", "A12", "A13", "A14",
]  # fmt: skip

AttackCategory = Literal[
    "direct_injection",
    "argument_hijack",
    "exfiltration",
    "tool_poisoning",
    "confused_deputy",
    "ledger_poisoning",
    "endorsement_abuse",
]


class ExpectedOutcome(NotaryModel):
    verdict: Verdict
    deciding_check: CheckName | None


class AttackCase(NotaryModel):
    id: AttackId
    category: AttackCategory
    title: str
    payload: str
    expected: ExpectedOutcome
