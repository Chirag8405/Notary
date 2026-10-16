"""Canonical JSON and hashing helpers. Shared by the audit chain and the contract digest."""

import json

import pytest
from builders import contract
from hypothesis import given
from hypothesis import strategies as st

from notary_core.canon import canonical_hash, canonical_json, sha256_hex
from notary_core.models import IntentContract

# Hypothesis strategy for nested JSON-like values without floats.
JSON_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(),
    lambda children: st.lists(children) | st.dictionaries(st.text(), children),
    max_leaves=20,
)


# covers: I5
def test_key_order_does_not_matter() -> None:
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})
    assert canonical_json({"b": {"y": 1, "x": 2}, "a": 1}) == '{"a":1,"b":{"x":2,"y":1}}'


# covers: I5
def test_no_whitespace_and_unicode_kept() -> None:
    text = canonical_json({"k": ["é", 1]})
    assert text == '{"k":["é",1]}'
    assert "\\u" not in text


# covers: I5
def test_floats_rejected() -> None:
    with pytest.raises(ValueError, match="floats are not allowed in canonical JSON"):
        canonical_json(1.5)
    with pytest.raises(ValueError, match="floats are not allowed"):
        canonical_json({"a": [1, {"b": 2.0}]})
    with pytest.raises(ValueError, match="floats are not allowed"):
        canonical_json(({"a": 0.1},))


# covers: I5
def test_nan_rejected() -> None:
    with pytest.raises(ValueError, match="floats are not allowed"):
        canonical_json(float("nan"))
    with pytest.raises(ValueError, match="floats are not allowed"):
        canonical_json({"a": float("inf")})


# covers: I5
def test_sha256_known_vector() -> None:
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_hex("abc") == expected


# covers: I5
def test_canonical_hash_stable_across_equal_models() -> None:
    first = contract()
    second = IntentContract.model_validate_json(first.model_dump_json())
    assert canonical_hash(first) == canonical_hash(second)
    changed = first.model_copy(update={"user_intent": first.user_intent + "!"})
    assert canonical_hash(changed) != canonical_hash(first)


# covers: I5
@given(JSON_VALUES)
def test_canonical_json_is_deterministic(value: object) -> None:
    text = canonical_json(value)
    assert text == canonical_json(value)
    assert json.loads(text) == value
    # Re-serializing the parsed result is a fixed point.
    assert canonical_json(json.loads(text)) == text
