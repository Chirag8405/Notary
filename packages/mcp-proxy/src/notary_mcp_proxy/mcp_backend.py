"""A `ToolBackend` over a real MCP server: manifests, argument types, result fields, metering."""

import json
from collections.abc import Mapping

from pydantic import JsonValue, TypeAdapter, ValidationError

from notary_core.gateway import ToolResultField
from notary_core.models import NotaryModel, ToolEffect
from notary_core.pinning import ToolManifest
from notary_core.policy.sensitive_params import PolicyTable, effective_effect, param_policy
from notary_core.units import canonicalize_amount, to_cents
from notary_mcp_proxy.backend import (
    BackendEffect,
    BackendRecord,
    BackendResult,
    schema_text,
)
from notary_mcp_proxy.client import ServerError, StdioClient
from notary_mcp_proxy.jsonrpc import JsonObject, as_list, as_object, as_str

RESULT_RECORD = "result"
"""Record id of a call's result; its values are `<call_id>.result.<field>`."""
NON_STRING_TYPES = frozenset({"integer", "number", "boolean", "object", "array", "null"})
FAIL_CLOSED_READERS: tuple[str, ...] = ("user",)
"""Readers of a tool the config does not name (it cannot pass the scope check anyway)."""

_JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


def encode_argument(value: JsonValue) -> str:
    """The text the Gateway labels for one MCP argument: a string as is, anything else as JSON."""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def decode_argument(text: str, schema_type: str | None) -> JsonValue:
    """Back to the type the tool's schema declares; text that does not parse stays text."""
    if schema_type not in NON_STRING_TYPES:
        return text
    try:
        return _JSON.validate_json(text)
    except ValidationError:
        return text


def content_fields(answer: JsonObject) -> tuple[ToolResultField, ...]:
    """One field per content block: a text block's text, any other block as JSON."""
    fields: list[ToolResultField] = []
    for index, block in enumerate(as_list(answer.get("content")) or []):
        entry = as_object(block)
        text = (
            as_str(entry.get("text")) if entry is not None and entry.get("type") == "text" else None
        )
        if text is None:
            text = encode_argument(block)
        fields.append(ToolResultField(name=f"content_{index:03d}", text=text, unit=None))
    return tuple(fields)


class PinnedTool(NotaryModel):
    """A tool definition as the server reported it; everything but `_meta` is pinned."""

    name: str
    title: str | None
    description: str
    input_schema: JsonObject
    output_schema: JsonObject | None
    annotations: JsonObject | None
    icons: list[JsonValue] | None


def pinned_text(tool: PinnedTool) -> str:
    """Canonical envelope handed to core as `ToolManifest.input_schema`.

    Sorted keys, absent keys omitted, so key order and whitespace of the server do not matter.
    `_meta` is transport metadata and is not part of it.
    """
    envelope: JsonObject = {"inputSchema": tool.input_schema}
    optional: dict[str, JsonValue | None] = {
        "outputSchema": tool.output_schema,
        "title": tool.title,
        "annotations": tool.annotations,
        "icons": tool.icons,
    }
    envelope.update({key: value for key, value in optional.items() if value is not None})
    return schema_text(envelope)


def parse_tool(raw: JsonObject) -> PinnedTool:
    name = as_str(raw.get("name"))
    if name is None:
        raise ServerError("a tool has no name")
    schema = raw.get("inputSchema")
    if schema is not None and as_object(schema) is None:
        raise ServerError(f"tool {name}: inputSchema is not an object")
    output = raw.get("outputSchema")
    if output is not None and as_object(output) is None:
        raise ServerError(f"tool {name}: outputSchema is not an object")
    return PinnedTool(
        name=name,
        title=as_str(raw.get("title")),
        description=as_str(raw.get("description")) or "",
        input_schema=as_object(schema) or {},
        output_schema=as_object(output),
        annotations=as_object(raw.get("annotations")),
        icons=as_list(raw.get("icons")),
    )


def exposed_definition(tool: PinnedTool) -> JsonObject:
    """What the agent is shown (`outputSchema` is not exposed yet)."""
    shown: JsonObject = {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    }
    if tool.title is not None:
        shown["title"] = tool.title
    if tool.annotations is not None:
        shown["annotations"] = tool.annotations
    return shown


class McpBackend:
    def __init__(
        self,
        client: StdioClient,
        *,
        policy: PolicyTable,
        effects: Mapping[str, ToolEffect],
        readers: Mapping[str, tuple[str, ...]],
    ) -> None:
        self._client = client
        self._policy = policy
        self._effects = dict(effects)
        self._readers = dict(readers)
        self._pinned: dict[str, PinnedTool] = {}

    def list_tools(self) -> tuple[ToolManifest, ...]:
        manifests: list[ToolManifest] = []
        for raw in self._client.list_tools():
            tool = parse_tool(raw)
            self._pinned.setdefault(tool.name, tool)
            manifests.append(
                ToolManifest(
                    name=tool.name, description=tool.description, input_schema=pinned_text(tool)
                )
            )
        return tuple(manifests)

    def pinned_definitions(self) -> tuple[PinnedTool, ...]:
        """The definitions from the first listing of each tool (what the agent is shown)."""
        return tuple(self._pinned.values())

    def call_tool(self, tool: str, args: Mapping[str, str]) -> BackendResult:
        pinned = self._pinned.get(tool)
        properties = as_object((pinned.input_schema if pinned else {}).get("properties")) or {}
        arguments: JsonObject = {
            name: decode_argument(text, as_str((as_object(properties.get(name)) or {}).get("type")))
            for name, text in args.items()
        }
        try:
            answer = self._client.call_tool(tool, arguments)
        except ServerError as failure:
            return BackendResult(records=(), effect=None, error=str(failure))
        fields = content_fields(answer)
        if answer.get("isError") is True:
            message = "\n".join(field.text for field in fields) or "tool error"
            return BackendResult(records=(), effect=None, error=message)
        readers = self._readers.get(tool, FAIL_CLOSED_READERS)
        records = (
            (BackendRecord(record_id=RESULT_RECORD, readers=readers, fields=fields),)
            if fields
            else ()
        )
        return BackendResult(records=records, effect=self._effect(tool, args, fields), error=None)

    def _effect(
        self, tool: str, args: Mapping[str, str], fields: tuple[ToolResultField, ...]
    ) -> BackendEffect:
        """Spend and egress measured the way the budget step measures them."""
        cents = 0
        egress = 0
        for name, text in args.items():
            kind = param_policy(self._policy, tool, name).kind
            if kind == "amount":
                cents += to_cents(canonicalize_amount(text)) or 0
            elif kind == "payload":
                egress += len(text.encode("utf-8"))
        effect = effective_effect(self._policy, tool, self._effects.get(tool))
        return BackendEffect(
            summary=f"{tool}: {len(fields)} content block(s)",
            spent_cents=cents,
            egress_bytes=egress,
            mutating=effect != "read",
        )
