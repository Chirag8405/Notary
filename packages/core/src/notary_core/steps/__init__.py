"""Monitor steps, one module per check in `CHECK_ORDER`, and the `STEPS` registry."""

from notary_core.models import CheckName
from notary_core.pipeline import Step
from notary_core.steps.budget import check_budget
from notary_core.steps.confidentiality import check_confidentiality
from notary_core.steps.corroboration import check_corroboration
from notary_core.steps.irreversibility import check_irreversibility
from notary_core.steps.origin import check_origin
from notary_core.steps.scope import check_scope

STEPS: tuple[tuple[CheckName, Step], ...] = (
    ("scope", check_scope),
    ("irreversibility", check_irreversibility),
    ("origin", check_origin),
    ("corroboration", check_corroboration),
    ("confidentiality", check_confidentiality),
    ("budget", check_budget),
)
"""The six checks in `CHECK_ORDER`."""
