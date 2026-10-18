"""JSON-RPC 2.0 framed as one JSON object per line: the MCP stdio transport."""

import json
from typing import IO

from pydantic import JsonValue, TypeAdapter, ValidationError

JsonObject = dict[str, JsonValue]

_OBJECT: TypeAdapter[JsonObject] = TypeAdapter(JsonObject)

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class MessageError(Exception):
    """A line that is not a JSON object."""


def read_message(stream: IO[bytes]) -> JsonObject | None:
    """The next message, or None at end of stream. Blank lines are skipped."""
    while True:
        line = stream.readline()
        if not line:
            return None
        if line.strip():
            break
    try:
        return _OBJECT.validate_json(line)
    except ValidationError as error:
        raise MessageError("not a JSON object") from error


def write_message(stream: IO[bytes], message: JsonObject) -> None:
    text = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    stream.write(text.encode("utf-8") + b"\n")
    stream.flush()


def result(request_id: JsonValue, value: JsonObject) -> JsonObject:
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def error(request_id: JsonValue, code: int, message: str) -> JsonObject:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def as_object(value: JsonValue | None) -> JsonObject | None:
    return value if isinstance(value, dict) else None


def as_list(value: JsonValue | None) -> list[JsonValue] | None:
    return value if isinstance(value, list) else None


def as_str(value: JsonValue | None) -> str | None:
    return value if isinstance(value, str) else None
