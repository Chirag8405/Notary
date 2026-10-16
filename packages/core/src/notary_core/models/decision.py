"""Tool call proposals and monitor decisions."""

from typing import Literal

from notary_core.models.labels import NotaryModel, ValueRef

CheckName = Literal[
    "scope",
    "irreversibility",
    "origin",
    "corroboration",
    "confidentiality",
    "budget",
]
"""Monitor checks, listed in the order they are evaluated."""

CHECK_ORDER: tuple[CheckName, ...] = (
    "scope",
    "irreversibility",
    "origin",
    "corroboration",
    "confidentiality",
    "budget",
)

Verdict = Literal["ALLOW", "ESCALATE", "BLOCK"]
CheckOutcome = Literal["pass", "escalate", "fail"]


class ToolCallProposal(NotaryModel):
    call_id: str
    tool: str
    args: dict[str, ValueRef]


class Reason(NotaryModel):
    check: CheckName
    outcome: CheckOutcome
    detail: str


class Decision(NotaryModel):
    verdict: Verdict
    reasons: tuple[Reason, ...]
    """Ordered to match `CHECK_ORDER`."""
