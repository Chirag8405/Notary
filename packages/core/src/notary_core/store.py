"""The Value Store: an immutable store of labeled values, and values derived from stored ones.

The store satisfies the frozen `ValueStore` Protocol of `notary_core.gateway`; `as_mapping()` is
what `decide()` receives as `values`. Derived values never gain authority: they take the lowest
integrity and the narrowest readers of their inputs. Pure: no I/O, clock or randomness.
"""

from collections.abc import Iterable, Mapping, Sequence
from types import MappingProxyType

from notary_core.canon import sha256_hex
from notary_core.models import DecisionUnit, Label, Origin, ResolvedValue, SpanPointer, ValueRef
from notary_core.provenance import derive_label


class ValueStoreError(Exception):
    """Base class for Value Store errors."""


class ValueIdCollisionError(ValueStoreError):
    """The same id was given two different values."""


def _merged(
    base: Mapping[str, ResolvedValue], values: Iterable[ResolvedValue]
) -> dict[str, ResolvedValue]:
    merged = dict(base)
    for value in values:
        known = merged.get(value.ref.id)
        if known is not None and known != value:
            raise ValueIdCollisionError(f"value id collision: {value.ref.id}")
        merged[value.ref.id] = value
    return dict(sorted(merged.items()))


class InMemoryValueStore:
    """Immutable: every update returns a new store, and a failed update changes nothing."""

    def __init__(self, values: Iterable[ResolvedValue] = ()) -> None:
        self._by_id: dict[str, ResolvedValue] = _merged({}, values)

    def get(self, value_id: str) -> ResolvedValue | None:
        return self._by_id.get(value_id)

    def with_values(self, values: Iterable[ResolvedValue]) -> "InMemoryValueStore":
        return InMemoryValueStore(_merged(self._by_id, values).values())

    def as_mapping(self) -> Mapping[str, ResolvedValue]:
        """Read-only, keyed by `ValueRef.id`, iterated in sorted id order."""
        return MappingProxyType(self._by_id)

    def ids(self) -> tuple[str, ...]:
        return tuple(self._by_id)

    def values(self) -> tuple[ResolvedValue, ...]:
        return tuple(self._by_id.values())

    def __len__(self) -> int:
        return len(self._by_id)

    def __contains__(self, value_id: object) -> bool:
        return value_id in self._by_id


def content_hash_ok(value: ResolvedValue) -> bool:
    """Whether the text still hashes to the hash in the reference (the monitor checks this too)."""
    return sha256_hex(value.text) == value.ref.content_hash


def span_resolves(value: ResolvedValue, store: Mapping[str, ResolvedValue]) -> bool:
    """The monitor's span rule: no pointer, or an existing source and `0 <= start <= end <= len`."""
    pointer = value.ref.label.span_pointer
    if pointer is None:
        return True
    source = store.get(pointer.source_value_id)
    return source is not None and 0 <= pointer.start <= pointer.end <= len(source.text)


def derive_value(
    inputs: Sequence[ResolvedValue],
    *,
    value_id: str,
    text: str,
    unit: DecisionUnit | None,
    origin: Origin,
    span_source: str | None = None,
) -> ResolvedValue:
    """A value derived from `inputs`: lowest integrity, narrowest readers.

    With `span_source` (the id of exactly one input) the new value points at the first occurrence
    of `text` in that input; without it the value claims no span.
    """
    if not inputs:
        raise ValueError("derive_value needs at least one input")
    label = derive_label([value.ref.label for value in inputs], origin)
    if span_source is not None:
        sources = [value for value in inputs if value.ref.id == span_source]
        if len(sources) != 1:
            raise ValueError("span_source must be one of the inputs")
        start = sources[0].text.find(text)
        if start < 0:
            raise ValueError("text is not a substring of the span source")
        label = Label(
            origin=label.origin,
            integrity=label.integrity,
            readers=label.readers,
            span_pointer=SpanPointer(
                source_value_id=span_source, start=start, end=start + len(text)
            ),
        )
    ref = ValueRef(id=value_id, label=label, content_hash=sha256_hex(text))
    return ResolvedValue(ref=ref, unit=unit, text=text)
