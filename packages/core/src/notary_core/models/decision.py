"""Tool call proposals and monitor decisions."""

from typing import Literal, Self

from pydantic import model_validator

from notary_core.models.labels import NotaryModel, Sha256Hex, ValueRef
from notary_core.models.ledger import DiffCard

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

ReasonCode = Literal[
    "STEP_PASS",
    "READ_ONLY_UNGATED",
    "SCOPE_TOOL_NOT_IN_CONTRACT",
    "SCOPE_MANIFEST_MISMATCH",
    "SCOPE_PARAM_NOT_IN_CONTRACT",
    "IRREVERSIBLE_NOT_AUTHORIZED",
    "ORIGIN_UNTRUSTED",
    "ORIGIN_UNSOURCED",
    "ORIGIN_LITERAL_MISMATCH",
    "ORIGIN_SOURCE_MISMATCH",
    "LEDGER_EXACT_MATCH",
    "LEDGER_LOOKALIKE",
    "LEDGER_NOVEL_ESCALATE",
    "LEDGER_NOT_FOUND",
    "CONF_READER_VIOLATION",
    "CONF_URL_NOT_ALLOWED",
    "CONF_CONTEXT_ESCALATE",
    "BUDGET_AMOUNT",
    "BUDGET_SENDS",
    "BUDGET_EGRESS_BYTES",
    "BUDGET_APPROVALS_EXHAUSTED",
    "BUDGET_ESCALATIONS_EXHAUSTED",
]
"""Machine-readable reason for a step result. Each code belongs to exactly one check."""

CODE_CHECK: dict[ReasonCode, CheckName | None] = {
    "STEP_PASS": None,
    "READ_ONLY_UNGATED": "scope",
    "SCOPE_TOOL_NOT_IN_CONTRACT": "scope",
    "SCOPE_MANIFEST_MISMATCH": "scope",
    "SCOPE_PARAM_NOT_IN_CONTRACT": "scope",
    "IRREVERSIBLE_NOT_AUTHORIZED": "irreversibility",
    "ORIGIN_UNTRUSTED": "origin",
    "ORIGIN_UNSOURCED": "origin",
    "ORIGIN_LITERAL_MISMATCH": "origin",
    "ORIGIN_SOURCE_MISMATCH": "origin",
    "LEDGER_EXACT_MATCH": "corroboration",
    "LEDGER_LOOKALIKE": "corroboration",
    "LEDGER_NOVEL_ESCALATE": "corroboration",
    "LEDGER_NOT_FOUND": "corroboration",
    "CONF_READER_VIOLATION": "confidentiality",
    "CONF_URL_NOT_ALLOWED": "confidentiality",
    "CONF_CONTEXT_ESCALATE": "confidentiality",
    "BUDGET_AMOUNT": "budget",
    "BUDGET_SENDS": "budget",
    "BUDGET_EGRESS_BYTES": "budget",
    "BUDGET_APPROVALS_EXHAUSTED": "budget",
    "BUDGET_ESCALATIONS_EXHAUSTED": "budget",
}
"""None = valid for any check."""

PASS_CODES: frozenset[ReasonCode] = frozenset(
    {"STEP_PASS", "READ_ONLY_UNGATED", "LEDGER_EXACT_MATCH"}
)
ESCALATE_CODES: frozenset[ReasonCode] = frozenset(
    {"LEDGER_NOVEL_ESCALATE", "CONF_CONTEXT_ESCALATE"}
)
"""The only codes an `escalate` outcome may carry: a new value (step 4) or text written after a
private read (step 5)."""


class ToolCallProposal(NotaryModel):
    call_id: str
    tool: str
    manifest_hash: Sha256Hex
    """Observed hash of the tool's CURRENT manifest. Stamped by the Gateway, never by the LLM."""
    args: dict[str, ValueRef]


class Reason(NotaryModel):
    check: CheckName
    outcome: CheckOutcome
    code: ReasonCode
    detail: str

    @model_validator(mode="after")
    def _code_matches_check_and_outcome(self) -> Self:
        owner = CODE_CHECK[self.code]
        if owner is not None and owner != self.check:
            raise ValueError(f"code {self.code} belongs to check {owner}, not {self.check}")
        if self.outcome == "pass":
            if self.code not in PASS_CODES:
                raise ValueError(f"outcome pass requires a pass code, got {self.code}")
        elif self.outcome == "escalate":
            if self.code not in ESCALATE_CODES:
                raise ValueError(f"outcome escalate requires an escalate code, got {self.code}")
        elif self.code in PASS_CODES or self.code in ESCALATE_CODES:
            raise ValueError(f"outcome fail cannot use code {self.code}")
        return self


class StepOutcome(NotaryModel):
    """What a monitor step returns unless it passes silently (None).

    Internal to the monitor: deliberately not exported to the JSON Schema.
    """

    verdict: Literal["ALLOW", "BLOCK", "ESCALATE"]
    code: ReasonCode
    detail: str
    diff_card: DiffCard | None
    """Only meaningful when verdict is ESCALATE; must be None otherwise."""

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.verdict != "ESCALATE" and self.diff_card is not None:
            raise ValueError("diff_card is only allowed for ESCALATE")
        if self.verdict == "ALLOW" and self.code not in PASS_CODES:
            raise ValueError("ALLOW requires a pass code")
        if self.verdict == "ESCALATE" and self.code not in ESCALATE_CODES:
            raise ValueError("ESCALATE requires an escalate code")
        if self.verdict == "BLOCK" and (self.code in PASS_CODES or self.code in ESCALATE_CODES):
            raise ValueError("BLOCK requires a failing code")
        return self


class Decision(NotaryModel):
    verdict: Verdict
    reasons: tuple[Reason, ...]
    """Ordered like `CHECK_ORDER`. Evaluation stops at the first BLOCK, so this may be a prefix."""
    diff_card: DiffCard | None
    """Present only for ESCALATE: the endorsement card built from labels."""

    @model_validator(mode="after")
    def _verdict_matches_reasons(self) -> Self:
        if not self.reasons:
            raise ValueError("a decision needs at least one reason")
        positions = [CHECK_ORDER.index(r.check) for r in self.reasons]
        if positions != sorted(set(positions)):
            raise ValueError("reasons must follow CHECK_ORDER without repeats")
        failed = any(r.outcome == "fail" for r in self.reasons)
        escalated = any(r.outcome == "escalate" for r in self.reasons)
        if self.verdict == "ALLOW" and (failed or escalated):
            raise ValueError("ALLOW cannot have failing or escalating reasons")
        if self.verdict == "BLOCK" and not failed:
            raise ValueError("BLOCK requires a failing reason")
        if self.verdict == "ESCALATE" and (failed or not escalated):
            raise ValueError("ESCALATE requires an escalating reason and no failing reason")
        if self.verdict != "ESCALATE" and self.diff_card is not None:
            raise ValueError("diff_card is only allowed for ESCALATE")
        return self
