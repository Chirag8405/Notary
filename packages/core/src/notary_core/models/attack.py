"""Attack library entries (A1-A14)."""

from typing import Literal, Self

from pydantic import model_validator

from notary_core.models.decision import CheckName, ReasonCode, Verdict
from notary_core.models.labels import NotaryModel

AttackId = Literal[
    "A1", "A2", "A3", "A4", "A5", "A6", "A7",
    "A8", "A9", "A10", "A11", "A12", "A13", "A14",
]  # fmt: skip

AttackCategory = Literal[
    "instruction_override",
    "authority_impersonation",
    "data_only_poisoning",
    "action_induction",
    "exfiltration",
    "staged_long_horizon",
    "obfuscation",
    "lookalike",
    "trust_laundering",
    "tool_poisoning",
    "approval_phishing",
    "side_channel",
    "text_to_text_deception",
    "denial_of_utility",
]

ATTACK_CATEGORY: dict[AttackId, AttackCategory] = {
    "A1": "instruction_override",
    "A2": "authority_impersonation",
    "A3": "data_only_poisoning",
    "A4": "action_induction",
    "A5": "exfiltration",
    "A6": "staged_long_horizon",
    "A7": "obfuscation",
    "A8": "lookalike",
    "A9": "trust_laundering",
    "A10": "tool_poisoning",
    "A11": "approval_phishing",
    "A12": "side_channel",
    "A13": "text_to_text_deception",
    "A14": "denial_of_utility",
}
"""Each attack id has exactly one category (the taxonomy in docs/threat-model.md)."""


class ExpectedOutcome(NotaryModel):
    verdict: Verdict
    deciding_check: CheckName | None
    """The check that decides the verdict; None when every check passes (ALLOW)."""
    code: ReasonCode | None
    """Expected reason code of the deciding check, if one is pinned."""


class AttackCase(NotaryModel):
    id: AttackId
    category: AttackCategory
    title: str
    payload: str
    expected: ExpectedOutcome

    @model_validator(mode="after")
    def _category_matches_id(self) -> Self:
        if ATTACK_CATEGORY[self.id] != self.category:
            raise ValueError(
                f"{self.id} has category {ATTACK_CATEGORY[self.id]}, not {self.category}"
            )
        return self
