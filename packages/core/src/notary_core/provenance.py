"""Provenance helpers: derived values take the lowest integrity and narrowest readers.

Readers encoding: a tuple containing `PUBLIC` means "anyone may read"; the empty tuple means
"nobody". Joining readers is an intersection with `PUBLIC` as the identity, and every join output
goes through `normalize_readers`, so equal reader sets always serialize identically.
"""

from collections.abc import Iterable, Sequence

from notary_core.models import Integrity, Label, Origin

PUBLIC: str = "*"
"""A readers tuple containing "*" means "anyone may read"."""

INTEGRITY_ORDER: tuple[Integrity, ...] = ("untrusted", "endorsed", "trusted")
"""Lowest first."""


def lowest_integrity(items: Iterable[Integrity]) -> Integrity:
    ranks = [INTEGRITY_ORDER.index(item) for item in items]
    if not ranks:
        raise ValueError("lowest_integrity needs at least one integrity")
    return INTEGRITY_ORDER[min(ranks)]


def normalize_readers(readers: Iterable[str]) -> tuple[str, ...]:
    """Sorted, unique; any `PUBLIC` collapses the whole set to `(PUBLIC,)`."""
    unique = set(readers)
    if PUBLIC in unique:
        return (PUBLIC,)
    return tuple(sorted(unique))


def join_readers(a: Sequence[str], b: Sequence[str]) -> tuple[str, ...]:
    """Intersection with `PUBLIC` as identity. An empty tuple means nobody."""
    left = normalize_readers(a)
    right = normalize_readers(b)
    if left == (PUBLIC,):
        return right
    if right == (PUBLIC,):
        return left
    return normalize_readers(set(left) & set(right))


def join_all_readers(items: Iterable[Sequence[str]]) -> tuple[str, ...]:
    """Fold with `join_readers` from `(PUBLIC,)`; an empty iterable gives `(PUBLIC,)`."""
    joined: tuple[str, ...] = (PUBLIC,)
    for readers in items:
        joined = join_readers(joined, readers)
    return joined


def readers_allow(readers: Sequence[str], principal: str) -> bool:
    return PUBLIC in readers or principal in readers


def derive_label(inputs: Sequence[Label], origin: Origin) -> Label:
    """Lowest integrity, narrowest readers. Never claims a span: callers build a new `Label`."""
    if not inputs:
        raise ValueError("derive_label needs at least one input label")
    return Label(
        origin=origin,
        integrity=lowest_integrity(label.integrity for label in inputs),
        readers=normalize_readers(join_all_readers(label.readers for label in inputs)),
        span_pointer=None,
    )
