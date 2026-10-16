"""Provenance helpers: integrity lattice, readers join and derive_label."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from notary_core.models import (
    EmailOrigin,
    Integrity,
    Label,
    LlmOrigin,
    ToolOrigin,
    UserOrigin,
)
from notary_core.provenance import (
    INTEGRITY_ORDER,
    PUBLIC,
    derive_label,
    join_all_readers,
    join_readers,
    lowest_integrity,
    normalize_readers,
    readers_allow,
)

INTEGRITIES = st.sampled_from(INTEGRITY_ORDER)
PRINCIPALS = st.sampled_from(("a", "b", "c", "d", "user"))
READERS = st.lists(PRINCIPALS | st.just(PUBLIC), max_size=5).map(tuple)
PRIVATE_READERS = st.lists(PRINCIPALS, max_size=5).map(tuple)


def _label(integrity: Integrity, readers: tuple[str, ...] = (PUBLIC,)) -> Label:
    origin = UserOrigin(kind="user") if integrity == "trusted" else EmailOrigin(kind="email")
    return Label(origin=origin, integrity=integrity, readers=readers, span_pointer=None)


def _llm() -> LlmOrigin:
    return LlmOrigin(kind="llm")


# covers: I2
def test_derived_integrity_is_lowest_of_inputs() -> None:
    assert lowest_integrity(("trusted", "untrusted")) == "untrusted"
    assert lowest_integrity(("trusted", "endorsed")) == "endorsed"
    assert derive_label((_label("trusted"), _label("untrusted")), _llm()).integrity == "untrusted"
    assert derive_label((_label("trusted"), _label("endorsed")), _llm()).integrity == "endorsed"


# covers: A6
@given(st.lists(INTEGRITIES, min_size=1, max_size=6))
def test_untrusted_never_upgrades(integrities: list[Integrity]) -> None:
    inputs = tuple(_label(integrity) for integrity in integrities)
    derived = derive_label(inputs, _llm())
    rank = INTEGRITY_ORDER.index(derived.integrity)
    assert all(rank <= INTEGRITY_ORDER.index(label.integrity) for label in inputs)
    if "untrusted" in integrities:
        assert derived.integrity == "untrusted"


# covers: A6
def test_labels_do_not_decay_across_stages() -> None:
    email = _label("untrusted")
    calendar = Label(
        origin=ToolOrigin(kind="tool", name="calendar"),
        integrity="trusted",
        readers=(PUBLIC,),
        span_pointer=None,
    )
    stage1 = derive_label((email, calendar), _llm())
    stage2 = derive_label((stage1, calendar), _llm())
    stage3 = derive_label((calendar, stage2), ToolOrigin(kind="tool", name="summarize"))
    assert (stage1.integrity, stage2.integrity, stage3.integrity) == ("untrusted",) * 3


# covers: I3
def test_join_readers_is_intersection() -> None:
    assert join_readers(("a", "b"), ("b", "c")) == ("b",)
    assert join_all_readers((("a", "b"), ("b", "c"), ("c", "b"))) == ("b",)


# covers: I3
@given(PRIVATE_READERS)
def test_public_is_identity_for_join(readers: tuple[str, ...]) -> None:
    assert join_readers((PUBLIC,), readers) == tuple(sorted(set(readers)))
    assert join_readers(readers, (PUBLIC,)) == tuple(sorted(set(readers)))
    assert join_readers((PUBLIC,), (PUBLIC,)) == (PUBLIC,)
    assert join_all_readers(()) == (PUBLIC,)


# covers: I3
@given(READERS, READERS, READERS)
def test_join_is_commutative_and_associative(
    a: tuple[str, ...], b: tuple[str, ...], c: tuple[str, ...]
) -> None:
    assert join_readers(a, b) == join_readers(b, a)
    assert join_readers(join_readers(a, b), c) == join_readers(a, join_readers(b, c))
    assert join_all_readers((a, b, c)) == join_readers(join_readers(a, b), c)


# covers: I3
def test_empty_readers_means_nobody() -> None:
    assert join_readers((), (PUBLIC,)) == ()
    assert join_readers((PUBLIC,), ()) == ()
    assert join_readers((), ("a",)) == ()
    assert readers_allow((), "user") is False
    assert readers_allow(("a",), "user") is False
    assert readers_allow(("a", "user"), "user") is True
    assert readers_allow((PUBLIC,), "user") is True


# covers: I3
@given(st.lists(READERS, min_size=1, max_size=5))
def test_derived_readers_subset_of_each_input(inputs: list[tuple[str, ...]]) -> None:
    labels = tuple(_label("untrusted", readers) for readers in inputs)
    derived = set(derive_label(labels, _llm()).readers)
    for readers in inputs:
        if PUBLIC not in readers:
            assert derived <= set(readers)


# covers: model
def test_derive_label_rejects_empty_inputs() -> None:
    with pytest.raises(ValueError, match="at least one input"):
        derive_label((), _llm())
    with pytest.raises(ValueError, match="at least one integrity"):
        lowest_integrity(())


# covers: model
def test_derive_label_never_claims_a_span() -> None:
    derived = derive_label((_label("trusted", ("user",)),), ToolOrigin(kind="tool", name="t"))
    assert derived.span_pointer is None
    assert derived.origin == ToolOrigin(kind="tool", name="t")
    assert derived.readers == ("user",)


# covers: I3
def test_wildcard_collapses_to_public() -> None:
    assert normalize_readers(("a", PUBLIC, "b")) == (PUBLIC,)
    assert join_readers(("a", PUBLIC), ("b",)) == ("b",)
    assert join_readers(("a", PUBLIC), ("b", PUBLIC)) == (PUBLIC,)
    assert join_all_readers((("a", PUBLIC), ("*", "*"))) == (PUBLIC,)
    assert derive_label((_label("untrusted", ("a", PUBLIC)),), _llm()).readers == (PUBLIC,)


# covers: I3
@given(st.lists(READERS, max_size=5))
def test_join_output_is_canonical(inputs: list[tuple[str, ...]]) -> None:
    joined = join_all_readers(inputs)
    assert joined == normalize_readers(joined)
    assert joined == tuple(sorted(set(joined)))
    assert PUBLIC not in joined or joined == (PUBLIC,)
    if inputs:
        pair = join_readers(inputs[0], inputs[-1])
        assert pair == normalize_readers(pair)
        # Order and duplicates in the inputs never change the output.
        assert join_all_readers(reversed(inputs)) == joined
        assert join_all_readers(tuple(r + r for r in inputs)) == joined
        derived = derive_label(tuple(_label("untrusted", r) for r in inputs), _llm())
        assert derived.readers == joined
