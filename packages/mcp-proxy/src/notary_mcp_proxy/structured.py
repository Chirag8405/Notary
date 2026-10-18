"""Structured tool results: one leaf per field, and the exact way back.

A leaf is `(path, text, type)`. `flatten` turns a JSON value into leaves, `unflatten` turns leaves
back into the same value. Paths are `prefix` plus key segments joined by `.`:

    {"items": [{"iban": "DE00"}]}  ->  structured.items.0.iban

Segments. An array index is its decimal digits (`0`, `12`; no leading zero). An object key is
escaped so that a path never reads two ways: `\\` becomes `\\\\`, `.` becomes `\\.`, `*` becomes
`\\*`, and a key that is empty or starts with a digit gets a `\\#` in front (`\\#` alone is the
empty key, `\\#0` is the key "0"). So a key can never be taken for an index or a wildcard, two
different values never share a path, and `unflatten` rejects any path that is not exactly what
`flatten` writes.

Config patterns (`matches`) use the same segments relative to the root, with an unescaped `*` that
stands for exactly one array index. Nothing else is a wildcard.
"""

import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Literal

from pydantic import JsonValue, TypeAdapter, ValidationError

from notary_mcp_proxy.jsonrpc import JsonObject, as_list, as_object, as_str

JsonLeafType = Literal["string", "number", "integer", "boolean", "null", "object", "array"]
"""`object` and `array` only for an empty container, which is a leaf with text `{}` / `[]`."""
Leaf = tuple[str, str, JsonLeafType]

_JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
PREFIX = "structured"
MAX_DEPTH = 32
MAX_LEAVES = 2000
"""Bounds on what one result may hold; more fails closed instead of flooding the audit log."""

_LEAF_TYPES: frozenset[str] = frozenset(
    {"string", "number", "integer", "boolean", "null", "object", "array"}
)
_INDEX = re.compile(r"(?:0|[1-9][0-9]*)")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)")
_ESCAPES = {"\\": "\\", ".": ".", "*": "*", "#": ""}


class StructureError(ValueError):
    """A result or a path that cannot be represented or rebuilt exactly. The caller fails closed."""


def is_index(segment: str) -> bool:
    return _INDEX.fullmatch(segment) is not None


def escape_key(key: str) -> str:
    """One object key as a path segment."""
    escaped = key.replace("\\", "\\\\").replace(".", "\\.").replace("*", "\\*")
    if not escaped or escaped[0].isdigit():
        return "\\#" + escaped
    return escaped


def unescape_segment(segment: str) -> str:
    """The key a segment stands for; raises for anything `escape_key` would not write."""
    out: list[str] = []
    chars = iter(segment)
    for char in chars:
        if char != "\\":
            out.append(char)
            continue
        following = next(chars, None)
        if following is None or following not in _ESCAPES:
            raise StructureError(f"bad escape in path segment {segment!r}")
        out.append(_ESCAPES[following])
    key = "".join(out)
    if escape_key(key) != segment:
        raise StructureError(f"path segment {segment!r} is not canonical")
    return key


def split_path(path: str) -> tuple[str, ...]:
    """Raw segments of a path without its prefix; `""` is the root (no segments)."""
    if not path:
        return ()
    segments: list[str] = []
    current: list[str] = []
    chars = iter(path)
    for char in chars:
        if char == "\\":
            following = next(chars, None)
            if following is None:
                raise StructureError(f"path {path!r} ends in a lone backslash")
            current.append(char + following)
        elif char == ".":
            segments.append("".join(current))
            current = []
        else:
            current.append(char)
    segments.append("".join(current))
    if any(not segment for segment in segments):
        raise StructureError(f"path {path!r} has an empty segment")
    return tuple(segments)


def join_path(segments: Iterable[str]) -> str:
    return ".".join(segments)


def relative(path: str, prefix: str = PREFIX) -> str:
    """The path below the prefix (`""` for the prefix itself)."""
    if path == prefix:
        return ""
    if path.startswith(prefix + "."):
        return path[len(prefix) + 1 :]
    raise StructureError(f"path {path!r} is not under {prefix!r}")


def _scalar(value: JsonValue) -> tuple[str, JsonLeafType]:
    if value is None:
        return "null", "null"
    if isinstance(value, bool):
        return ("true" if value else "false"), "boolean"
    if isinstance(value, int):
        return str(value), "integer"
    if isinstance(value, float):
        if not math.isfinite(value):
            raise StructureError("a number is not finite")
        return json.dumps(value), "number"
    if isinstance(value, str):
        return value, "string"
    raise StructureError("not a JSON scalar")


def flatten(value: JsonValue, prefix: str = PREFIX) -> tuple[Leaf, ...]:
    """One leaf per scalar (and per empty object or array), in document order."""
    leaves: list[Leaf] = []

    def walk(node: JsonValue, path: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise StructureError(f"nesting deeper than {MAX_DEPTH}")
        if isinstance(node, dict):
            if not node:
                leaves.append((path, "{}", "object"))
            for key, child in node.items():
                walk(child, f"{path}.{escape_key(key)}", depth + 1)
        elif isinstance(node, list):
            if not node:
                leaves.append((path, "[]", "array"))
            for index, child in enumerate(node):
                walk(child, f"{path}.{index}", depth + 1)
        else:
            text, kind = _scalar(node)
            leaves.append((path, text, kind))
        if len(leaves) > MAX_LEAVES:
            raise StructureError(f"more than {MAX_LEAVES} fields")

    walk(value, prefix, 0)
    return tuple(leaves)


def _parse(text: str, kind: str) -> JsonValue:
    """The value a leaf stands for; the text must be exactly what `flatten` writes for it."""
    if kind == "string":
        return text
    if kind == "null" and text == "null":
        return None
    if kind == "boolean" and text in ("true", "false"):
        return text == "true"
    if kind == "object" and text == "{}":
        return {}
    if kind == "array" and text == "[]":
        return []
    if kind == "integer" and _INTEGER.fullmatch(text):
        return int(text)
    if kind == "number":
        try:
            number = json.loads(text)
        except ValueError:
            number = None
        if isinstance(number, float) and math.isfinite(number) and json.dumps(number) == text:
            return number
    raise StructureError(f"text does not fit type {kind!r}")


class _Node:
    def __init__(self) -> None:
        self.children: dict[str, _Node] = {}
        self.leaf: tuple[JsonValue] | None = None


def _build(node: _Node) -> JsonValue:
    if node.leaf is not None:
        if node.children:
            raise StructureError("a path is both a value and a container")
        return node.leaf[0]
    if not node.children:
        raise StructureError("empty node")
    segments = list(node.children)
    if all(is_index(segment) for segment in segments):
        ordered = sorted(segments, key=int)
        if [int(segment) for segment in ordered] != list(range(len(ordered))):
            raise StructureError("array indexes are not 0..n-1")
        return [_build(node.children[segment]) for segment in ordered]
    if any(is_index(segment) or segment[:1].isdigit() for segment in segments):
        raise StructureError("an object has an index segment")
    out: dict[str, JsonValue] = {}
    for segment in segments:
        out[unescape_segment(segment)] = _build(node.children[segment])
    return out


def unflatten(leaves: Sequence[Leaf], prefix: str = PREFIX) -> JsonValue:
    """The exact inverse of `flatten`; raises `StructureError` for leaves it could not have made."""
    root = _Node()
    for path, text, kind in leaves:
        if kind not in _LEAF_TYPES:
            raise StructureError(f"unknown leaf type {kind!r}")
        node = root
        for segment in split_path(relative(path, prefix)):
            node = node.children.setdefault(segment, _Node())
        if node.leaf is not None:
            raise StructureError(f"two leaves share the path {path!r}")
        node.leaf = (_parse(text, kind),)
    if not leaves:
        raise StructureError("no leaves")
    return _build(root)


TYPES_FIELD = "structured_types"
"""Field (next to `structured.*`) that records the type of every leaf that is not a string."""


def types_text(leaves: Sequence[Leaf]) -> str | None:
    """JSON `{path: type}` for the non-string leaves, so the rebuild is exact; None if none."""
    kinds = {path: kind for path, _, kind in leaves if kind != "string"}
    if not kinds:
        return None
    return json.dumps(kinds, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def leaves_from(texts: Mapping[str, str], types: str | None) -> tuple[Leaf, ...]:
    """Leaves from labeled texts (path -> text) and the types text that was labeled with them."""
    kinds: dict[str, JsonLeafType] = {}
    if types is not None:
        try:
            decoded = _JSON.validate_json(types)
        except ValidationError as failure:
            raise StructureError("the type map is not JSON") from failure
        entries = as_object(decoded)
        if entries is None:
            raise StructureError("the type map is not an object")
        for path, kind in entries.items():
            name = as_str(kind)
            if name is None or name == "string" or name not in _LEAF_TYPES:
                raise StructureError("the type map has a bad type")
            if path not in texts:
                raise StructureError("the type map names a field that is not there")
            kinds[path] = "string" if name == "string" else _narrow(name)
    return tuple((path, text, kinds.get(path, "string")) for path, text in texts.items())


def _narrow(name: str) -> JsonLeafType:
    for kind in ("number", "integer", "boolean", "null", "object", "array"):
        if name == kind:
            return kind
    raise StructureError(f"unknown leaf type {name!r}")


def compact(value: JsonValue) -> str:
    """The one JSON text the agent is given for a rebuilt structure."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def matches(pattern: str, path: str) -> bool:
    """`pattern` and `path` are relative; `*` in a pattern is exactly one array index."""
    wanted = split_path(pattern)
    actual = split_path(path)
    if len(wanted) != len(actual):
        return False
    return all(
        want == have or (want == "*" and is_index(have))
        for want, have in zip(wanted, actual, strict=True)
    )


def covers(pattern: str, path: str) -> bool:
    """`pattern` matches `path` or one of its ancestors (a container pattern covers its leaves)."""
    wanted = split_path(pattern)
    actual = split_path(path)
    if not wanted or len(wanted) > len(actual):
        return False
    return matches(pattern, join_path(actual[: len(wanted)]))


def specificity(pattern: str) -> tuple[int, int]:
    """Longer patterns win; among equals the one with fewer wildcards."""
    segments = split_path(pattern)
    return len(segments), -segments.count("*")


def validate_pattern(pattern: str) -> None:
    """A config pattern: canonical segments, `*` only as a whole segment."""
    segments = split_path(pattern)
    if not segments:
        raise StructureError("empty field pattern")
    for segment in segments:
        if segment == "*" or is_index(segment):
            continue
        unescape_segment(segment)


def declared(path: str, schema: frozenset[str]) -> bool:
    """Whether the output schema declares this (relative) data path; indexes count as `*`."""
    generic = join_path("*" if is_index(segment) else segment for segment in split_path(path))
    return generic in schema


_REF_DEPTH = 16


def schema_paths(output_schema: JsonObject) -> frozenset[str]:
    """Every path the output schema declares: object properties by key, array items as `*`.

    Follows `allOf` / `anyOf` / `oneOf` and local `$ref`s (a `$ref` already being followed is not
    followed again, so a recursive type stops there). Keys that the schema does not name are not
    declared, whatever `additionalProperties` says.
    """
    found: set[str] = set()

    def resolve(ref: str) -> JsonObject | None:
        if not ref.startswith("#"):
            return None
        node: JsonValue = output_schema
        for part in [p for p in ref[1:].split("/") if p]:
            child = as_object(node)
            if child is None:
                return None
            node = child.get(part.replace("~1", "/").replace("~0", "~"))
        return as_object(node)

    def walk(schema: JsonValue, base: tuple[str, ...], refs: tuple[str, ...], depth: int) -> None:
        node = as_object(schema)
        if node is None or depth > _REF_DEPTH * 2:
            return
        ref = as_str(node.get("$ref"))
        if ref is not None and ref not in refs:
            target = resolve(ref)
            if target is not None:
                walk(target, base, (*refs, ref), depth + 1)
        for combiner in ("allOf", "anyOf", "oneOf"):
            for option in as_list(node.get(combiner)) or []:
                walk(option, base, refs, depth + 1)
        properties = as_object(node.get("properties")) or {}
        for name, child in properties.items():
            path = (*base, escape_key(name))
            found.add(join_path(path))
            walk(child, path, refs, depth + 1)
        items = node.get("items")
        listed = as_list(items) if isinstance(items, list) else None
        item_schemas: list[JsonValue] = [*(listed or []), *(as_list(node.get("prefixItems")) or [])]
        if not isinstance(items, list):
            item_schemas.append(items)
        for item in item_schemas:
            if as_object(item) is None:
                continue
            path = (*base, "*")
            found.add(join_path(path))
            walk(item, path, refs, depth + 1)

    walk(output_schema, (), (), 0)
    return frozenset(found)
