"""Step 3: every argument exists in the Value Store, is intact and satisfies its marker."""

from notary_core.canon import sha256_hex
from notary_core.models import Marker, Origin, ResolvedValue, ToolOrigin, ValueRef
from notary_core.models.decision import StepOutcome
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import effective_marker
from notary_core.units import canonicalize


def _block(code: str, detail: str) -> StepOutcome:
    return StepOutcome.model_validate(
        {"verdict": "BLOCK", "code": code, "detail": detail, "diff_card": None}
    )


ORIGIN_KINDS: frozenset[str] = frozenset({"user", "tool", "email", "file", "web", "ledger", "llm"})
"""Every `Origin.kind`. A bare `named_source` name that equals one of these means that origin."""


def origin_matches_source(origin: Origin, source: str) -> bool:
    """Whether `origin` is the origin a `named_source` marker's `source` names.

    A tool origin matches its tool name; every other origin matches its kind. A tool named like
    an origin kind (a tool called `email`) never matches, so it cannot pass for that origin
    (fail closed); the bare name stays reserved for the origin kind.
    """
    if isinstance(origin, ToolOrigin):
        return origin.name == source and source not in ORIGIN_KINDS
    return origin.kind == source


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
        if not origin_matches_source(label.origin, marker.source):
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
    if sha256_hex(resolved.text) != resolved.ref.content_hash:
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
