"""Canonical JSON and hashing helpers. Shared by the audit chain and the contract digest."""

import json
from decimal import Decimal
from typing import cast

import pytest
from core_builders import contract
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


@pytest.mark.invariant("I5")
def test_key_order_does_not_matter() -> None:
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})
    assert canonical_json({"b": {"y": 1, "x": 2}, "a": 1}) == '{"a":1,"b":{"x":2,"y":1}}'


@pytest.mark.invariant("I5")
def test_no_whitespace_and_unicode_kept() -> None:
    text = canonical_json({"k": ["é", 1]})
    assert text == '{"k":["é",1]}'
    assert "\\u" not in text


@pytest.mark.invariant("I5")
def test_floats_rejected() -> None:
    with pytest.raises(ValueError, match="floats are not allowed in canonical JSON"):
        canonical_json(1.5)
    with pytest.raises(ValueError, match="floats are not allowed"):
        canonical_json({"a": [1, {"b": 2.0}]})
    with pytest.raises(ValueError, match="floats are not allowed"):
        canonical_json(({"a": 0.1},))


@pytest.mark.invariant("I5")
def test_nan_rejected() -> None:
    with pytest.raises(ValueError, match="floats are not allowed"):
        canonical_json(float("nan"))
    with pytest.raises(ValueError, match="floats are not allowed"):
        canonical_json({"a": float("inf")})


@pytest.mark.invariant("I5")
def test_sha256_known_vector() -> None:
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_hex("abc") == expected


@pytest.mark.invariant("I5")
def test_canonical_hash_stable_across_equal_models() -> None:
    first = contract()
    second = IntentContract.model_validate_json(first.model_dump_json())
    assert canonical_hash(first) == canonical_hash(second)
    changed = first.model_copy(update={"user_intent": first.user_intent + "!"})
    assert canonical_hash(changed) != canonical_hash(first)


def _reversed_copy(value: object) -> object:
    """Deep copy with every dict rebuilt in reversed insertion order."""
    if isinstance(value, dict):
        items = cast(dict[str, object], value).items()
        return {key: _reversed_copy(item) for key, item in reversed(list(items))}
    if isinstance(value, list):
        return [_reversed_copy(item) for item in cast(list[object], value)]
    return value


@pytest.mark.invariant("I5")
def test_non_str_keys_rejected() -> None:
    with pytest.raises(TypeError, match="keys must be str"):
        canonical_json({1: "x"})
    with pytest.raises(TypeError, match="keys must be str"):
        canonical_json({None: "x"})
    with pytest.raises(TypeError, match="keys must be str"):
        canonical_json([{"a": {True: 1}}])


@pytest.mark.invariant("I5")
def test_non_json_types_rejected() -> None:
    for value in ({1}, b"x", Decimal("1"), object()):
        with pytest.raises(TypeError, match="not allowed in canonical JSON"):
            canonical_json(value)
        with pytest.raises(TypeError, match="not allowed in canonical JSON"):
            canonical_json({"a": [value]})


@pytest.mark.invariant("I5")
def test_bool_and_int_hash_differently() -> None:
    assert canonical_json(True) == "true"
    assert canonical_json(1) == "1"
    assert sha256_hex(canonical_json(True)) != sha256_hex(canonical_json(1))
    assert canonical_json({"a": True}) != canonical_json({"a": 1})


@pytest.mark.invariant("I5")
def test_lone_surrogate_hashes_deterministically() -> None:
    expected = "91a681b998555fb475479817b126c94e57e52011fa1842c5d188795a4a05226b"
    assert sha256_hex("\ud800") == expected
    assert sha256_hex("\ud800") == sha256_hex("\ud800")
    assert sha256_hex(canonical_json({"k": "\ud800"})) == sha256_hex(
        canonical_json({"k": "\ud800"})
    )


@pytest.mark.invariant("I5")
@given(JSON_VALUES)
def test_canonical_json_is_deterministic(value: object) -> None:
    text = canonical_json(value)
    assert text == canonical_json(_reversed_copy(value))
    assert text == canonical_json(value)
    assert json.loads(text) == value
    # Re-serializing the parsed result is a fixed point.
    assert canonical_json(json.loads(text)) == text
