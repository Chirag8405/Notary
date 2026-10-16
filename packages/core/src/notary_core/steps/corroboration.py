"""Step 4: untrusted values must be corroborated by the trusted ledger, by decision unit."""

from collections.abc import Sequence
from typing import Literal

from notary_core.ledger import entries_for, find_exact
from notary_core.lookalike import is_lookalike, nearest_known
from notary_core.models import DecisionUnit, DiffCard, DiffRow, ValueRef
from notary_core.models.decision import StepOutcome
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import effective_marker, param_policy
from notary_core.units import canonicalize

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


def _block(
    code: Literal["LEDGER_LOOKALIKE", "LEDGER_NOT_FOUND", "ORIGIN_UNSOURCED"], detail: str
) -> StepOutcome:
    return StepOutcome(verdict="BLOCK", code=code, detail=detail, diff_card=None)


def check_corroboration(inp: StepInput) -> StepOutcome | None:
    """Corroborate guarded arguments that are not fully trusted against the ledger.

    Only arguments under a `ledger` or `endorse` marker are in scope, and only when their
    STORED integrity is not "trusted": `endorsed` is not enough on its own, because a derived
    value inherits it without the user endorsing that exact value. Labels and text come from the
    Value Store, never from the proposal. For each in-scope argument, in sorted order:
    an exact canonical match corroborates it; else a near match is a BLOCK (lookalike, even under
    `endorse`); else a `ledger` marker BLOCKs (not found) and an `endorse` marker ESCALATEs.
    The first BLOCK wins and carries no card. Otherwise any ESCALATE returns one card with a row
    per escalating argument; otherwise at least one corroborated argument gives ALLOW, which
    later steps can still overrule. Validity is informational and never read here.
    """
    rows: list[DiffRow] = []
    corroborated = False
    for param in sorted(inp.proposal.args):
        ref = inp.proposal.args[param]
        proposed = None if inp.scope is None else inp.scope.params.get(param)
        marker = effective_marker(inp.policy, inp.proposal.tool, param, proposed)
        if marker.kind not in ("ledger", "endorse"):
            continue
        resolved = inp.values.get(ref.id)
        if resolved is None:
            return _block("ORIGIN_UNSOURCED", DETAIL_UNSOURCED)
        if resolved.ref.label.integrity == "trusted":
            continue
        unit = param_policy(inp.policy, inp.proposal.tool, param).unit or "identifier"
        canonical = canonicalize(unit, resolved.text).value
        # A `ledger` marker searches only the named ledger, an `endorse` marker every ledger of
        # the unit. The same scope applies to the lookalike candidates and the diff card.
        ledger_name = marker.ledger if marker.kind == "ledger" else None
        if find_exact(inp.ledger, unit, canonical, ledger_name) is not None:
            corroborated = True
            continue
        known = [entry.canonical for entry in entries_for(inp.ledger, unit, ledger_name)]
        if is_lookalike(unit, canonical, known) is not None:
            return _block("LEDGER_LOOKALIKE", DETAIL_LOOKALIKE)
        if marker.kind == "ledger":
            return _block("LEDGER_NOT_FOUND", DETAIL_NOT_FOUND)
        rows.append(build_diff_row(param, resolved.ref, canonical, known, unit))
    if rows:
        return StepOutcome(
            verdict="ESCALATE",
            code="LEDGER_NOVEL_ESCALATE",
            detail=DETAIL_NOVEL,
            diff_card=DiffCard(rows=tuple(rows)),
        )
    if corroborated:
        return StepOutcome(
            verdict="ALLOW", code="LEDGER_EXACT_MATCH", detail=DETAIL_MATCH, diff_card=None
        )
    return None
