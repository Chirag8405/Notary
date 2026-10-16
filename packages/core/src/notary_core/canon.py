"""Deterministic serialization and hashing shared by the audit chain and the contract digest."""

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import cast

from pydantic import BaseModel


def _reject_floats(obj: object) -> None:
    if isinstance(obj, float):
        raise ValueError("floats are not allowed in canonical JSON")
    if isinstance(obj, Mapping):
        for key, value in cast(Mapping[object, object], obj).items():
            _reject_floats(key)
            _reject_floats(value)
    elif isinstance(obj, Sequence) and not isinstance(obj, str | bytes | bytearray):
        for item in cast(Sequence[object], obj):
            _reject_floats(item)


def canonical_json(obj: object) -> str:
    """Sorted keys, compact separators, no ASCII escaping; any float is rejected."""
    _reject_floats(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_hash(model: BaseModel) -> str:
    return sha256_hex(canonical_json(model.model_dump(mode="json")))
