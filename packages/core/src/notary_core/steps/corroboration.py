"""Step 4: untrusted values must be corroborated by the trusted ledger, by decision unit."""

from collections.abc import Sequence

from notary_core.lookalike import nearest_known
from notary_core.models import DecisionUnit, DiffRow, ValueRef

DETAIL_LOOKALIKE = "value is a near match of a known value"
DETAIL_NOT_FOUND = "value is not in the ledger"
DETAIL_NOVEL = "value is new and needs endorsement"
DETAIL_MATCH = "value matches the ledger"
DETAIL_UNSOURCED = "argument value is not in the value store"
"""Details are constant strings and never echo attacker-controlled text."""


def build_diff_row(
    param: str, ref: ValueRef, canonical: str, known: Sequence[str], unit: DecisionUnit
) -> DiffRow:
    """Diff-card row for `param`. `ref` must be the stored value's reference, so that origin and
    integrity come from the stored label; the preview is the canonical value by design."""
    nearest = nearest_known(unit, canonical, known)
    return DiffRow(
        param=param,
        value_id=ref.id,
        origin=ref.label.origin,
        integrity=ref.label.integrity,
        preview=canonical,
        nearest_ledger_value=None if nearest is None else nearest[0],
        differing_positions=() if nearest is None else nearest[1],
    )
