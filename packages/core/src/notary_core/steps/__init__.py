"""Monitor steps, one module per check in `CHECK_ORDER`, and the `STEPS` registry."""

from notary_core.models import CheckName
from notary_core.models.decision import StepOutcome
from notary_core.pipeline import Step, StepInput
from notary_core.steps.budget import check_budget
from notary_core.steps.irreversibility import check_irreversibility
from notary_core.steps.scope import check_scope


def not_implemented_step(inp: StepInput) -> StepOutcome | None:
    """Placeholder for a step whose issue has not landed yet. Replace it in `STEPS`."""
    raise NotImplementedError("this monitor step is not implemented yet")


STEPS: tuple[tuple[CheckName, Step], ...] = (
    ("scope", check_scope),
    ("irreversibility", check_irreversibility),
    ("origin", not_implemented_step),
    ("corroboration", not_implemented_step),
    ("confidentiality", not_implemented_step),
    ("budget", check_budget),
)
"""The six checks in `CHECK_ORDER`. Each step issue replaces its placeholder."""
