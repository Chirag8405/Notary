"""Deterministic serialization and hashing shared by the audit chain and the contract digest."""

import hashlib
import json
from collections.abc import Sequence
from typing import cast

from pydantic import BaseModel


def _validate(obj: object) -> None:
    """Pre-walk: only dict, list, tuple, str, int, bool and None, with str keys, no floats."""
    if isinstance(obj, float):
        raise ValueError("floats are not allowed in canonical JSON")
    if obj is None or isinstance(obj, str | int):  # bool is an int
        return
    if isinstance(obj, dict):
        for key, value in cast(dict[object, object], obj).items():
            if not isinstance(key, str):
                raise TypeError(
                    f"canonical JSON dict keys must be str, got {type(key).__name__}: {key!r}"
                )
            _validate(value)
    elif isinstance(obj, list | tuple):
        for item in cast(Sequence[object], obj):
            _validate(item)
    else:
        raise TypeError(f"{type(obj).__name__} is not allowed in canonical JSON")


def canonical_json(obj: object) -> str:
    """Sorted keys, compact separators, no ASCII escaping.

    Accepts only dict (str keys), list, tuple, str, int, bool and None. A float raises
    `ValueError`; a non-str key or any other type raises `TypeError`.

    Tuples and lists serialize identically by design, so a model and its JSON round trip hash
    the same. Keys are ordered by code point, which differs from JavaScript's UTF-16 code unit
    sort for astral characters; do not compare these strings with a JS-produced canonical form.
    """
    _validate(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def sha256_hex(text: str) -> str:
    """Hex SHA-256 of the UTF-8 encoding of `text`.

    Encodes with `surrogatepass` so strings with lone surrogates hash deterministically
    instead of raising. The encoded bytes are only ever hashed, never decoded.
    """
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def canonical_hash(model: BaseModel) -> str:
    return sha256_hex(canonical_json(model.model_dump(mode="json")))
