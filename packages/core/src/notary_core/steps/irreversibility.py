"""Step 2: irreversible tools run only when the user explicitly authorized them."""

from notary_core.models.decision import StepOutcome
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import effective_effect


def check_irreversibility(inp: StepInput) -> StepOutcome | None:
    """BLOCK an irreversible tool that the contract does not list in `authorized_irreversible`.

    The effect is the stricter of the table's and the contract's, so a contract cannot relax it.
    An unknown tool counts as irreversible (fail closed).
    """
    declared = None if inp.scope is None else inp.scope.effect
    effect = effective_effect(inp.policy, inp.proposal.tool, declared)
    authorized = inp.proposal.tool in inp.contract.authorized_irreversible
    if inp.scope is None or (effect == "irreversible" and not authorized):
        return StepOutcome(
            verdict="BLOCK",
            code="IRREVERSIBLE_NOT_AUTHORIZED",
            detail="irreversible action was not authorized in the request",
            diff_card=None,
        )
    return None
