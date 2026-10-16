"""Step 1: the tool and its parameters are within the contract, and the manifest is unchanged."""

from notary_core.models.decision import StepOutcome
from notary_core.pipeline import StepInput


def _block(code: str, detail: str) -> StepOutcome:
    return StepOutcome.model_validate(
        {"verdict": "BLOCK", "code": code, "detail": detail, "diff_card": None}
    )


def check_scope(inp: StepInput) -> StepOutcome | None:
    """BLOCK unless the tool is in the contract, its manifest hash matches and no argument is extra.

    Details are constant strings: they never echo tool or parameter names, which may be
    attacker-controlled (A12).
    """
    if inp.scope is None:
        return _block("SCOPE_TOOL_NOT_IN_CONTRACT", "tool is not in the contract")
    if inp.proposal.manifest_hash != inp.scope.manifest_hash:
        return _block("SCOPE_MANIFEST_MISMATCH", "tool manifest differs from the pinned manifest")
    if any(name not in inp.scope.params for name in inp.proposal.args):
        return _block("SCOPE_PARAM_NOT_IN_CONTRACT", "argument is not part of the contract")
    return None
