"""Gateway argument half: label what the agent typed, then hand tools the text that was judged.

The agent proposes raw text per parameter. `ArgumentResolver` turns each into a stored, labeled
value, so provenance survives: quoting an untrusted email makes the argument untrusted, and
quoting a secret restricts its readers. Labels come from where the data came from, never from
what the text says. The behavior is a port of the lane-B stand-in in `notary_world.executor`.
"""

from collections.abc import Mapping
from typing import Protocol

from notary_core.canon import sha256_hex
from notary_core.models import (
    DecisionUnit,
    Label,
    LlmOrigin,
    ResolvedValue,
    SpanPointer,
    ValueRef,
)
from notary_core.provenance import INTEGRITY_ORDER, join_all_readers, normalize_readers
from notary_core.units import canonicalize

MIN_MATCH_LEN: int = 4
"""Shortest text matched inside a stored value."""
CANONICAL_TOOL_UNITS: frozenset[DecisionUnit] = frozenset({"iban", "email", "url_host", "amount"})
"""Units whose canonical form is what a tool receives."""


class ArgResolver(Protocol):
    """Labels the raw text of one argument against the values already stored."""

    def __call__(
        self,
        *,
        call_id: str,
        tool: str,
        param: str,
        raw: str,
        unit: DecisionUnit | None,
        store: Mapping[str, ResolvedValue],
    ) -> ResolvedValue: ...


def _rank(value: ResolvedValue) -> tuple[int, str]:
    """Lowest integrity first, then the smallest id."""
    return (INTEGRITY_ORDER.index(value.ref.label.integrity), value.ref.id)


def _same_value(value: ResolvedValue, raw: str, unit: DecisionUnit | None) -> bool:
    if value.text.strip() == raw.strip():
        return True
    if unit is None:
        return False
    return canonicalize(unit, value.text).value == canonicalize(unit, raw).value


class ArgumentResolver:
    """Stateless; resolves one argument by three rules, in order.

    1. A stored value with the same text (or the same canonical form in `unit`) is reused as is.
    2. Text found inside a stored value is labeled like that value, with a span pointing at it.
    3. Anything else is model-authored: untrusted, with the readers of every stored value it
       quotes whole and, in its origin, the readers of the whole store (`context_readers`).

    Known limits: matching ignores readers (reuse and span-source selection pick by integrity and
    id, so hardening is a later lane-A task), and only a whole quote is a BLOCK: text that might
    re-type a secret is an ESCALATE in step 5.
    """

    def __call__(
        self,
        *,
        call_id: str,
        tool: str,
        param: str,
        raw: str,
        unit: DecisionUnit | None,
        store: Mapping[str, ResolvedValue],
    ) -> ResolvedValue:
        values = sorted(store.values(), key=lambda v: v.ref.id)
        # Rule 1: the stored value is returned unchanged (its label, unit and id are kept).
        same = [v for v in values if _same_value(v, raw, unit)]
        if same:
            return min(same, key=_rank)
        # Uniqueness of this id against existing store ids is the caller's responsibility.
        value_id = f"{call_id}.arg.{param}"
        text = raw.strip()
        # Rule 2: a span of a stored value inherits that value's origin, integrity and readers.
        if len(text) >= MIN_MATCH_LEN:
            containing = [v for v in values if text in v.text]
            if containing:
                source = min(containing, key=_rank)
                start = source.text.index(text)
                span = SpanPointer(
                    source_value_id=source.ref.id, start=start, end=start + len(text)
                )
                label = Label(
                    origin=source.ref.label.origin,
                    integrity=source.ref.label.integrity,
                    readers=source.ref.label.readers,
                    span_pointer=span,
                )
                ref = ValueRef(id=value_id, label=label, content_hash=sha256_hex(text))
                return ResolvedValue(ref=ref, unit=unit, text=text)
        # Rule 3: model-authored text, kept unstripped. Quoting a stored value whole restricts the
        # readers to the join of theirs. Text that does not quote one may still re-type a secret
        # (dashes, words, base64), so the origin also records the readers of the whole store and
        # step 5 asks the user before such text goes to a non-reader.
        readers = normalize_readers(
            join_all_readers(
                v.ref.label.readers
                for v in values
                if len(v.text.strip()) >= MIN_MATCH_LEN and v.text.strip() in raw
            )
        )
        context = normalize_readers(join_all_readers(v.ref.label.readers for v in values))
        label = Label(
            origin=LlmOrigin(kind="llm", context_readers=context),
            integrity="untrusted",
            readers=readers,
            span_pointer=None,
        )
        ref = ValueRef(id=value_id, label=label, content_hash=sha256_hex(raw))
        return ResolvedValue(ref=ref, unit=unit, text=raw)


def canonical_args(
    args: Mapping[str, ResolvedValue], units: Mapping[str, DecisionUnit | None]
) -> dict[str, str]:
    """The argument text a tool receives, in sorted parameter order.

    The monitor judges `canonicalize(unit, text).value` (never `.valid`), so the tool must run on
    that same text, or check and use disagree. The unit is the PARAMETER's (`units`, a missing key
    means none), never the stored value's, which may differ. Identifiers and free text pass
    unchanged: a contact name keeps its case, so that check-versus-use gap is accepted by design.
    Keys of `units` that are not in `args` are ignored.
    """
    out: dict[str, str] = {}
    for param in sorted(args):
        unit = units.get(param)
        text = args[param].text
        out[param] = canonicalize(unit, text).value if unit in CANONICAL_TOOL_UNITS else text
    return out
