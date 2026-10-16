"""Step 3: every argument exists in the Value Store, is intact and satisfies its marker."""

import hashlib

from notary_core.models import Marker, Origin, ResolvedValue, ToolOrigin, ValueRef
from notary_core.models.decision import StepOutcome
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import effective_marker
from notary_core.units import canonicalize


def _block(code: str, detail: str) -> StepOutcome:
    return StepOutcome.model_validate(
        {"verdict": "BLOCK", "code": code, "detail": detail, "diff_card": None}
    )


def origin_name(origin: Origin) -> str:
    """The name a `named_source` marker compares against: a tool's name, else the origin kind."""
    if isinstance(origin, ToolOrigin):
        return origin.name
    return origin.kind


def literal_text(value: str | int | bool) -> str:
    """Text form of a literal marker's value. Checked before `int` because `bool` is an `int`."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _span_resolves(inp: StepInput, resolved: ResolvedValue) -> bool:
    pointer = resolved.ref.label.span_pointer
    if pointer is None:
        return True
    source = inp.values.get(pointer.source_value_id)
    return source is not None and 0 <= pointer.start <= pointer.end <= len(source.text)


def _literal_matches(resolved: ResolvedValue, expected: str | int | bool) -> bool:
    expected_text = literal_text(expected)
    if resolved.unit is None:
        return resolved.text == expected_text
    return (
        canonicalize(resolved.unit, resolved.text).value
        == canonicalize(resolved.unit, expected_text).value
    )


def _marker_failure(marker: Marker, resolved: ResolvedValue) -> StepOutcome | None:
    label = resolved.ref.label
    if marker.kind == "literal":
        if not _literal_matches(resolved, marker.value):
            return _block(
                "ORIGIN_LITERAL_MISMATCH", "argument differs from the value in the request"
            )
    elif marker.kind == "named_source":
        if origin_name(label.origin) != marker.source:
            return _block("ORIGIN_SOURCE_MISMATCH", "argument does not come from the named source")
        if label.integrity != "trusted":
            return _block("ORIGIN_UNTRUSTED", "argument from the named source is not trusted")
    # free: unconstrained. ledger / endorse: untrusted values are corroborated in step 4.
    return None


def _integrity_failure(
    inp: StepInput, ref: ValueRef, resolved: ResolvedValue
) -> StepOutcome | None:
    """The value must be the stored one, hash-intact, with a span that resolves."""
    if resolved.ref != ref:
        return _block("ORIGIN_UNSOURCED", "argument does not match the stored value")
    digest = hashlib.sha256(resolved.text.encode("utf-8")).hexdigest()
    if digest != resolved.ref.content_hash:
        return _block("ORIGIN_UNSOURCED", "content hash mismatch")
    if not _span_resolves(inp, resolved):
        return _block("ORIGIN_UNSOURCED", "span does not resolve")
    return None


def check_origin(inp: StepInput) -> StepOutcome | None:
    """BLOCK an argument that is unknown, forged, altered, unresolvable or breaks its marker.

    Arguments are checked in sorted parameter order, so the first failing one is reported
    deterministically. Decisions use the stored label only, never the proposal's copy. Never
    ESCALATEs: `ledger` / `endorse` markers admit untrusted values here and step 4 corroborates
    them. Details are constant strings and never echo attacker-controlled text.
    """
    for param in sorted(inp.proposal.args):
        ref = inp.proposal.args[param]
        resolved = inp.values.get(ref.id)
        if resolved is None:
            return _block("ORIGIN_UNSOURCED", "argument value is not in the value store")
        failure = _integrity_failure(inp, ref, resolved)
        if failure is not None:
            return failure
        proposed = None if inp.scope is None else inp.scope.params.get(param)
        marker = effective_marker(inp.policy, inp.proposal.tool, param, proposed)
        failure = _marker_failure(marker, resolved)
        if failure is not None:
            return failure
    return None
