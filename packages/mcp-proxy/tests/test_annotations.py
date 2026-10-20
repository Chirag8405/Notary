"""The proxy passes a server's tool annotations through exactly as given and invents none."""

from notary_mcp_proxy.jsonrpc import JsonObject
from notary_mcp_proxy.mcp_backend import exposed_definition, parse_tool, pinned_text

FULL: JsonObject = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}


def _raw(annotations: JsonObject | None) -> JsonObject:
    raw: JsonObject = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
    if annotations is not None:
        raw["annotations"] = annotations
    return raw


def test_four_hints_pass_through_unchanged() -> None:
    assert exposed_definition(parse_tool(_raw(FULL)))["annotations"] == FULL


def test_partial_and_non_boolean_hints_are_not_completed_or_coerced() -> None:
    odd: JsonObject = {"readOnlyHint": "yes", "destructiveHint": 0}
    assert exposed_definition(parse_tool(_raw(odd)))["annotations"] == odd


def test_missing_annotations_stay_missing() -> None:
    assert "annotations" not in exposed_definition(parse_tool(_raw(None)))


def test_annotations_are_part_of_the_pinned_text() -> None:
    plain = pinned_text(parse_tool(_raw(None)))
    annotated = pinned_text(parse_tool(_raw(FULL)))
    assert plain != annotated
    assert "destructiveHint" in annotated
