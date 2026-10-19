"""A `ToolBackend` over a real MCP server: manifests, argument types, result fields, metering."""

import json
from collections.abc import Mapping
from typing import get_args

from pydantic import JsonValue, TypeAdapter, ValidationError

from notary_core.gateway import ToolResultField
from notary_core.models import DecisionUnit, NotaryModel, ToolEffect
from notary_core.pinning import ToolManifest
from notary_core.policy.sensitive_params import PolicyTable, effective_effect, param_policy
from notary_core.provenance import join_readers, normalize_readers
from notary_core.units import canonicalize_amount, to_cents
from notary_mcp_proxy.backend import (
    BackendEffect,
    BackendRecord,
    BackendResult,
    schema_text,
)
from notary_mcp_proxy.client import (
    McpClient,
    ServerError,
    ServerExitedError,
    ServerRejectedError,
    ServerTimeoutError,
    diagnostic,
    quoted,
)
from notary_mcp_proxy.config import FieldSpec, RecordReaders
from notary_mcp_proxy.jsonrpc import JsonObject, as_list, as_object, as_str
from notary_mcp_proxy.structured import (
    MAX_LEAVES,
    TYPES_FIELD,
    StructureError,
    covers,
    declared,
    flatten,
    relative,
    schema_paths,
    specificity,
    types_text,
)

RESULT_RECORD = "result"
"""Record id of the part of a call's result that has the tool's readers; its values are
`<call_id>.result.<field>`. Fields with other readers are in `result-1`, `result-2`, ..."""
ARG_RECORD = "arg"
"""Argument values are `<call_id>.arg.<param>`; a result record may not use that id."""
NON_STRING_TYPES = frozenset({"integer", "number", "boolean", "object", "array", "null"})
FAIL_CLOSED_READERS: tuple[str, ...] = ("user",)
"""Readers of a tool the config does not name (it cannot pass the scope check anyway)."""

ERR_TIMEOUT = "the tool did not answer in time; it may still have run"
ERR_EXITED = "the tool server is not running"
ERR_PROTOCOL = "the tool server broke the protocol"
ERR_TOOL = "the tool reported an error"
ERR_UNCHECKED = "the tool server could not be checked; the call did not run"
"""The only error texts the agent may see for a failure below the proxy. What the server wrote
goes to stderr (`ServerError.detail`) or, for a tool's own error content, through the labeler."""

_JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


def error_text(failure: ServerError) -> str:
    """The constant text for a failure of a call that was sent to the server."""
    if isinstance(failure, ServerTimeoutError):
        return ERR_TIMEOUT
    if isinstance(failure, ServerExitedError):
        return ERR_EXITED
    if isinstance(failure, ServerRejectedError):
        return ERR_TOOL
    return ERR_PROTOCOL


def unchecked_text(failure: ServerError) -> str:
    """The constant text for a call that failed before it was sent (the pre-flight listing)."""
    return ERR_EXITED if isinstance(failure, ServerExitedError) else ERR_UNCHECKED


def report(context: str, failure: ServerError) -> None:
    """The server's own words about a failure, on stderr only."""
    diagnostic(f"{context}: {type(failure).__name__}: {quoted(failure.detail)}")


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


def content_fields(
    answer: JsonObject, skip: frozenset[int] = frozenset()
) -> tuple[ToolResultField, ...]:
    """One field per content block: a text block's text, any other block as JSON.

    `skip` holds block indexes that are not labeled (the copies of `structuredContent`); the
    other blocks keep their index in the name.
    """
    fields: list[ToolResultField] = []
    for index, block in enumerate(as_list(answer.get("content")) or []):
        if index in skip:
            continue
        entry = as_object(block)
        text = (
            as_str(entry.get("text")) if entry is not None and entry.get("type") == "text" else None
        )
        if text is None:
            text = encode_argument(block)
        fields.append(ToolResultField(name=f"content_{index:03d}", text=text, unit=None))
    return tuple(fields)


def _canonical_json(value: JsonValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def duplicate_blocks(answer: JsonObject, structured: JsonObject) -> frozenset[int]:
    """Indexes of text blocks that only serialize `structuredContent` (the MCP compat copy).

    They are not labeled: such a copy would carry the tool's readers for every field and let a
    field the config marks secret be quoted from it. The agent gets one serialization rebuilt
    from the labeled fields instead (`ProxyServer`). A text block that differs in any way is not a
    duplicate and is labeled like any other block, with the tool's readers.
    """
    wanted = _canonical_json(structured)
    found: set[int] = set()
    for index, block in enumerate(as_list(answer.get("content")) or []):
        entry = as_object(block)
        text = (
            as_str(entry.get("text")) if entry is not None and entry.get("type") == "text" else None
        )
        if text is None:
            continue
        try:
            parsed: JsonValue = _JSON.validate_json(text)
        except ValidationError:
            continue
        if _canonical_json(parsed) == wanted:
            found.add(index)
    return frozenset(found)


def field_settings(
    path: str, config: Mapping[str, FieldSpec], schema: frozenset[str]
) -> tuple[tuple[str, ...] | None, DecisionUnit | None]:
    """Readers and unit the config sets for a leaf at `path` (relative); only declared paths.

    Each setting comes from the most specific pattern that covers the path and sets it.
    """
    if not config or not declared(path, schema):
        return None, None
    readers: tuple[str, ...] | None = None
    unit: DecisionUnit | None = None
    ranked = sorted(
        (pattern for pattern in config if covers(pattern, path)), key=specificity, reverse=True
    )
    for pattern in ranked:
        spec = config[pattern]
        if readers is None and spec.readers is not None:
            readers = spec.readers
        if unit is None and spec.unit is not None:
            unit = spec.unit
    return readers, unit


def result_records(
    answer: JsonObject,
    *,
    readers: tuple[str, ...],
    config: Mapping[str, FieldSpec],
    schema: frozenset[str],
) -> tuple[BackendRecord, ...]:
    """The result as records: text blocks, then one field per leaf of `structuredContent`.

    Raises `StructureError` when `structuredContent` is present but is not an object, is too big
    or deep, or would give two fields one name. Fields are grouped by readers: record `result`
    for the tool's readers, `result-1`, ... for the others in order of their first field name.
    """
    named: list[tuple[ToolResultField, tuple[str, ...]]] = []
    tool_readers = normalize_readers(readers)
    if "structuredContent" in answer:
        structured = as_object(answer.get("structuredContent"))
        if structured is None:
            raise StructureError("structuredContent is not an object")
        leaves = flatten(structured)
        for field in content_fields(answer, duplicate_blocks(answer, structured)):
            named.append((field, tool_readers))
        kinds = types_text(leaves)
        if kinds is not None:
            named.append((ToolResultField(name=TYPES_FIELD, text=kinds, unit=None), tool_readers))
        for path, text, _ in leaves:
            own_readers, unit = field_settings(relative(path), config, schema)
            who = tool_readers if own_readers is None else normalize_readers(own_readers)
            named.append((ToolResultField(name=path, text=text, unit=unit), who))
    else:
        named.extend((field, tool_readers) for field in content_fields(answer))
    names = [field.name for field, _ in named]
    if len(set(names)) != len(names):
        raise StructureError("two result fields share a name")
    groups: dict[tuple[str, ...], list[ToolResultField]] = {}
    for field, who in named:
        groups.setdefault(who, []).append(field)
    others = sorted(
        (who for who in groups if who != tool_readers),
        key=lambda w: min(field.name for field in groups[w]),
    )
    records = (
        [
            BackendRecord(
                record_id=RESULT_RECORD, readers=tool_readers, fields=tuple(groups[tool_readers])
            )
        ]
        if tool_readers in groups
        else []
    )
    for number, who in enumerate(others, start=1):
        records.append(
            BackendRecord(
                record_id=f"{RESULT_RECORD}-{number}", readers=who, fields=tuple(groups[who])
            )
        )
    return tuple(records)


def _record_readers(
    entry: JsonObject, tool_readers: tuple[str, ...], mode: RecordReaders
) -> tuple[str, ...]:
    """The readers of one record: the tool's, narrowed (never widened) by the server's if asked."""
    if mode == "config":
        return tool_readers
    listed = as_list(entry.get("readers"))
    if listed is None or any(as_str(reader) is None for reader in listed):
        raise StructureError("a record has no readers list")
    return join_readers(tool_readers, [reader for reader in listed if isinstance(reader, str)])


def _record_field(raw: JsonValue) -> ToolResultField:
    entry = as_object(raw)
    if entry is None or set(entry) - {"name", "text", "unit"}:
        raise StructureError("a record field is not {name, text, unit}")
    name, text, unit = as_str(entry.get("name")), as_str(entry.get("text")), entry.get("unit")
    if not name or text is None:
        raise StructureError("a record field has no name or text")
    if unit is not None and not isinstance(unit, str):
        raise StructureError("a record field has an unknown unit")
    return ToolResultField(name=name, text=text, unit=None if unit is None else _unit(unit))


def _unit(text: str) -> DecisionUnit:
    for unit in get_args(DecisionUnit):
        if unit == text:
            return unit
    raise StructureError("a record field has an unknown unit")


def records_result(
    answer: JsonObject, *, readers: tuple[str, ...], mode: RecordReaders
) -> tuple[BackendRecord, ...]:
    """A result in the `records` shape: one record per entry of `structuredContent.records`.

    Each record keeps the server's `record_id`, so a value id is `<call_id>.<record_id>.<field>`;
    the fields keep their names and units. Text blocks that only copy `structuredContent` are
    dropped; any other text block is labeled with the tool's readers in record `result`
    (`content_NNN` fields), after the server's records. Raises `StructureError` for anything that
    is not exactly this shape, for a duplicate record id and for two values that would share an
    id, so nothing the server sent is left unlabeled or ambiguous.
    """
    structured = as_object(answer.get("structuredContent"))
    entries = None if structured is None else as_list(structured.get("records"))
    if structured is None or entries is None or set(structured) != {"records"}:
        raise StructureError("structuredContent is not {records: [...]}")
    tool_readers = normalize_readers(readers)
    records: list[BackendRecord] = []
    taken: set[str] = set()
    seen: set[str] = set()
    count = 0

    def add(record_id: str, who: tuple[str, ...], fields: tuple[ToolResultField, ...]) -> None:
        nonlocal count
        count += len(fields)
        if record_id in seen or record_id == ARG_RECORD or count > MAX_LEAVES:
            raise StructureError("duplicate or reserved record id, or too many fields")
        seen.add(record_id)
        for field in fields:
            value_id = f"{record_id}.{field.name}"
            if value_id in taken:
                raise StructureError("two result values share an id")
            taken.add(value_id)
        records.append(BackendRecord(record_id=record_id, readers=who, fields=fields))

    for raw in entries:
        entry = as_object(raw)
        if entry is None or set(entry) - {"record_id", "readers", "fields"}:
            raise StructureError("a record is not {record_id, readers, fields}")
        record_id = as_str(entry.get("record_id"))
        listed = as_list(entry.get("fields"))
        if not record_id or listed is None:
            raise StructureError("a record has no id or fields")
        add(
            record_id,
            _record_readers(entry, tool_readers, mode),
            tuple(_record_field(item) for item in listed),
        )
    extra = content_fields(answer, duplicate_blocks(answer, structured))
    if extra:
        add(RESULT_RECORD, tool_readers, extra)
    return tuple(records)


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
        raise ServerError(ERR_PROTOCOL, detail="a tool has no name")
    schema = raw.get("inputSchema")
    if schema is not None and as_object(schema) is None:
        raise ServerError(ERR_PROTOCOL, detail=f"tool {quoted(name)}: inputSchema is not an object")
    output = raw.get("outputSchema")
    if output is not None and as_object(output) is None:
        raise ServerError(
            ERR_PROTOCOL, detail=f"tool {quoted(name)}: outputSchema is not an object"
        )
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
    """What the agent is shown: the pinned definition without `_meta`."""
    shown: JsonObject = {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    }
    if tool.output_schema is not None:
        shown["outputSchema"] = tool.output_schema
    if tool.title is not None:
        shown["title"] = tool.title
    if tool.annotations is not None:
        shown["annotations"] = tool.annotations
    return shown


class McpBackend:
    def __init__(
        self,
        client: McpClient,
        *,
        policy: PolicyTable,
        effects: Mapping[str, ToolEffect],
        readers: Mapping[str, tuple[str, ...]],
        fields: Mapping[str, Mapping[str, FieldSpec]] | None = None,
        records: Mapping[str, RecordReaders] | None = None,
    ) -> None:
        self._client = client
        self._policy = policy
        self._effects = dict(effects)
        self._readers = dict(readers)
        self._fields = dict(fields or {})
        self._records: dict[str, RecordReaders] = dict(records or {})
        self._declared: dict[str, frozenset[str]] = {}
        self._pinned: dict[str, PinnedTool] = {}

    def list_tools(self) -> tuple[ToolManifest, ...]:
        manifests: list[ToolManifest] = []
        for raw in self._client.list_tools():
            tool = parse_tool(raw)
            if tool.name not in self._pinned:
                self._pinned[tool.name] = tool
                self._declared[tool.name] = schema_paths(tool.output_schema or {})
            manifests.append(
                ToolManifest(
                    name=tool.name, description=tool.description, input_schema=pinned_text(tool)
                )
            )
        return tuple(manifests)

    def unavailable(self) -> str | None:
        """The constant error text when the server is gone, else None."""
        return None if self._client.alive else ERR_EXITED

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
            report(f"call {tool}", failure)
            return BackendResult(records=(), effect=None, error=error_text(failure))
        try:
            records = self._records_of(tool, answer)
        except StructureError as failure:
            # The tool ran, but nothing of this result is handed on, so no spend is metered.
            diagnostic(f"call {tool}: bad structuredContent: {quoted(str(failure))}")
            return BackendResult(records=(), effect=None, error=ERR_PROTOCOL)
        if answer.get("isError") is True:
            # The server's error content is labeled like any result; only ERR_TOOL is ours.
            return BackendResult(records=records, effect=None, error=ERR_TOOL)
        blocks = len(as_list(answer.get("content")) or [])
        return BackendResult(
            records=records,
            effect=self._effect(tool, args, blocks, "structuredContent" in answer),
            error=None,
        )

    def _records_of(self, tool: str, answer: JsonObject) -> tuple[BackendRecord, ...]:
        readers = self._readers.get(tool, FAIL_CLOSED_READERS)
        mode = self._records.get(tool)
        if mode is not None and "structuredContent" in answer:
            return records_result(answer, readers=readers, mode=mode)
        return result_records(
            answer,
            readers=readers,
            config=self._fields.get(tool, {}),
            schema=self._declared.get(tool, frozenset()),
        )

    def _effect(
        self, tool: str, args: Mapping[str, str], blocks: int, structured: bool
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
            summary=f"{tool}: {blocks} content block(s)"
            + (", structuredContent" if structured else ""),
            spent_cents=cents,
            egress_bytes=egress,
            mutating=effect != "read",
        )
