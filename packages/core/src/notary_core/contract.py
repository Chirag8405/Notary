"""Contract monotonicity: nothing at runtime may widen the frozen `IntentContract` (I5)."""

from notary_core.canon import canonical_hash
from notary_core.models import (
    IntentContract,
    LedgerMarker,
    LiteralMarker,
    Marker,
    NamedSourceMarker,
    ToolScope,
)
from notary_core.policy.sensitive_params import EFFECT_STRICTNESS, marker_rank


class ContractWideningError(Exception):
    def __init__(self, reasons: tuple[str, ...]) -> None:
        self.reasons = reasons
        super().__init__("contract widened: " + "; ".join(reasons))


def digest(contract: IntentContract) -> str:
    return canonical_hash(contract)


def _marker_reason(old: Marker, new: Marker) -> str | None:
    """`None` when `new` is the same as `old` or stricter; else a short reason prefix."""
    if marker_rank(new) > marker_rank(old):
        return "marker relaxed"
    if isinstance(old, LiteralMarker) and isinstance(new, LiteralMarker):
        # `1 == True` in Python; the type check keeps a bool from standing in for an int.
        if type(old.value) is not type(new.value) or old.value != new.value:
            return "literal value changed"
    elif isinstance(old, NamedSourceMarker) and isinstance(new, NamedSourceMarker):
        if old.source != new.source:
            return "named source changed"
    elif (
        isinstance(old, LedgerMarker) and isinstance(new, LedgerMarker) and old.ledger != new.ledger
    ):
        return "ledger changed"
    return None


def _tool_reasons(old: ToolScope, new: ToolScope) -> set[str]:
    tool = new.tool
    reasons: set[str] = set()
    if new.manifest_hash != old.manifest_hash:
        reasons.add(f"manifest changed: {tool}")
    if EFFECT_STRICTNESS.index(new.effect) > EFFECT_STRICTNESS.index(old.effect):
        reasons.add(f"effect widened: {tool}")
    for param, marker in new.params.items():
        old_marker = old.params.get(param)
        if old_marker is None:
            reasons.add(f"param added: {tool}.{param}")
            continue
        reason = _marker_reason(old_marker, marker)
        if reason is not None:
            reasons.add(f"{reason}: {tool}.{param}")
    return reasons


def _budget_reasons(old: IntentContract, new: IntentContract) -> set[str]:
    reasons: set[str] = set()
    for field in type(new.budget).model_fields:
        if getattr(new.budget, field) > getattr(old.budget, field):
            reasons.add(f"budget widened: {field}")
    return reasons


def widening_reasons(old: IntentContract, new: IntentContract) -> tuple[str, ...]:
    """Sorted, one string per violation; empty means `new` is narrower than or equal to `old`.

    Removing tools or params, lowering budgets and tightening markers are not widenings.
    `user_intent` is free text and cannot be compared for "narrower", so it must stay equal.
    """
    reasons: set[str] = set()
    if new.contract_id != old.contract_id:
        reasons.add("contract_id changed")
    if new.user_intent != old.user_intent:
        reasons.add("user_intent changed")
    old_tools = {scope.tool: scope for scope in old.allowed_tools}
    for scope in new.allowed_tools:
        old_scope = old_tools.get(scope.tool)
        if old_scope is None:
            reasons.add(f"tool added: {scope.tool}")
        else:
            reasons |= _tool_reasons(old_scope, scope)
    reasons |= _budget_reasons(old, new)
    reasons.update(f"egress host added: {h}" for h in set(new.egress_hosts) - set(old.egress_hosts))
    reasons.update(
        f"irreversible authorization added: {t}"
        for t in set(new.authorized_irreversible) - set(old.authorized_irreversible)
    )
    return tuple(sorted(reasons))


def is_narrower_or_equal(old: IntentContract, new: IntentContract) -> bool:
    return widening_reasons(old, new) == ()


def assert_monotonic(old: IntentContract, new: IntentContract) -> None:
    reasons = widening_reasons(old, new)
    if reasons:
        raise ContractWideningError(reasons)
