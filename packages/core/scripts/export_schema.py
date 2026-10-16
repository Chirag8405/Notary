"""Export JSON Schema for every NOTARY model into packages/schema/json (deterministic).

This script lives outside `notary_core` so the package itself stays free of I/O.
"""

import json
import sys
from pathlib import Path
from typing import cast

from pydantic import BaseModel, TypeAdapter
from pydantic.json_schema import GenerateJsonSchema, JsonSchemaValue, models_json_schema
from pydantic_core import core_schema

from notary_core import models
from notary_core.models import Event, Marker, NotaryModel, Origin

JsonObject = dict[str, object]

OUT_DIR = Path(__file__).resolve().parents[2] / "schema" / "json"
REF_TEMPLATE = "#/$defs/{model}"
ABSTRACT_BASES = {"NotaryModel", "EventBase"}
UNION_ALIASES: dict[str, TypeAdapter[object]] = {
    "Event": TypeAdapter(Event),
    "Marker": TypeAdapter(Marker),
    "Origin": TypeAdapter(Origin),
}


class NotaryJsonSchema(GenerateJsonSchema):
    """Emit discriminated unions as `anyOf` (+ `discriminator`) instead of `oneOf`.

    `oneOf` forces generators to assert "exactly one match", which generates poor Zod;
    with a discriminator the two are equivalent.
    """

    def tagged_union_schema(self, schema: core_schema.TaggedUnionSchema) -> JsonSchemaValue:
        result = super().tagged_union_schema(schema)
        if "oneOf" in result:
            result["anyOf"] = result.pop("oneOf")
        return result


def model_classes() -> list[type[NotaryModel]]:
    found: list[type[NotaryModel]] = []
    for name in sorted(models.__all__):
        obj = getattr(models, name)
        if (
            isinstance(obj, type)
            and issubclass(obj, BaseModel)
            and issubclass(obj, NotaryModel)
            and name not in ABSTRACT_BASES
        ):
            found.append(obj)
    return found


def build_defs() -> dict[str, JsonObject]:
    classes = model_classes()
    _, top = models_json_schema(
        [(c, "validation") for c in classes],
        ref_template=REF_TEMPLATE,
        schema_generator=NotaryJsonSchema,
    )
    defs = cast("dict[str, JsonObject]", top.get("$defs", {}))
    for alias, adapter in UNION_ALIASES.items():
        schema = cast(
            "JsonObject",
            adapter.json_schema(ref_template=REF_TEMPLATE, schema_generator=NotaryJsonSchema),
        )
        nested = cast("dict[str, JsonObject]", schema.pop("$defs", {}))
        for name, definition in nested.items():
            existing = defs.setdefault(name, definition)
            if existing != definition:
                raise SystemExit(f"conflicting definitions for {name}")
        defs[alias] = schema
    deduped = _dedupe_aliases(defs)
    return {name: _titled(name, deduped[name]) for name in sorted(deduped)}


def _strip_titles(node: object) -> object:
    if isinstance(node, dict):
        return {k: _strip_titles(v) for k, v in cast("JsonObject", node).items() if k != "title"}
    if isinstance(node, list):
        return [_strip_titles(item) for item in cast("list[object]", node)]
    return node


def _titled(name: str, definition: JsonObject) -> JsonObject:
    """Drop Pydantic's per-field noise titles; keep exactly one title per definition."""
    stripped = cast("JsonObject", _strip_titles(definition))
    return {"title": name, **stripped}


def _without_title(schema: JsonObject) -> JsonObject:
    return cast("JsonObject", _strip_titles(schema))


def _replace_inline(node: object, targets: dict[str, JsonObject]) -> object:
    """Swap inline copies of a union alias for a `$ref`, so TS/Zod emit one named type."""
    if isinstance(node, dict):
        mapping = cast("JsonObject", node)
        stripped = _without_title(mapping)
        for alias, target in targets.items():
            if stripped == target:
                return {"$ref": REF_TEMPLATE.format(model=alias)}
        return {k: _replace_inline(v, targets) for k, v in mapping.items()}
    if isinstance(node, list):
        return [_replace_inline(item, targets) for item in cast("list[object]", node)]
    return node


def _dedupe_aliases(defs: dict[str, JsonObject]) -> dict[str, JsonObject]:
    targets = {alias: _without_title(defs[alias]) for alias in UNION_ALIASES}
    result: dict[str, JsonObject] = {}
    for name, definition in defs.items():
        if name in UNION_ALIASES:
            result[name] = definition
        else:
            result[name] = cast("JsonObject", _replace_inline(definition, targets))
    return result


def collect_refs(node: object, out: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in cast("JsonObject", node).items():
            if key == "$ref" and isinstance(value, str):
                out.add(value.removeprefix("#/$defs/"))
            else:
                collect_refs(value, out)
    elif isinstance(node, list):
        for item in cast("list[object]", node):
            collect_refs(item, out)


def closure(name: str, defs: dict[str, JsonObject]) -> dict[str, JsonObject]:
    seen: set[str] = set()
    stack = [name]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        refs: set[str] = set()
        collect_refs(defs[current], refs)
        stack.extend(refs)
    return {k: defs[k] for k in sorted(seen - {name})}


def dump(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    defs = build_defs()
    dialect = "https://json-schema.org/draft/2020-12/schema"
    dump(OUT_DIR / "notary.schema.json", {"$schema": dialect, "$defs": defs})

    models_dir = OUT_DIR / "models"
    for stale in models_dir.glob("*.schema.json"):
        stale.unlink()
    for name, definition in defs.items():
        single: JsonObject = {"$schema": dialect, **definition}
        nested = closure(name, defs)
        if nested:
            single["$defs"] = nested
        dump(models_dir / f"{name}.schema.json", single)
    sys.stdout.write(f"exported {len(defs)} schemas to {OUT_DIR}\n")


if __name__ == "__main__":
    main()
