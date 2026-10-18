"""A toy files MCP server (stdio, stdlib only) with a secret file.

It is one of the two "real MCP servers" the proxy fronts in the office example: it knows nothing
about NOTARY. Run alone it hands out any file it has.
"""

import json
import sys

SECRET = "sk-live-NOTARY-DEMO-7f3a9c41"
FILES = {
    "notes/plan.txt": "Status: the December report is done; the review is on Friday.",
    "secrets/api_key.txt": SECRET,
}
TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file by path.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "path of the file"}},
            "required": ["path"],
        },
    }
]


def call(name: str, arguments: dict[str, object]) -> dict[str, object]:
    if name == "read_file":
        text = FILES.get(str(arguments.get("path")))
        if text is not None:
            return {"content": [{"type": "text", "text": text}], "isError": False}
        return {"content": [{"type": "text", "text": "no such file"}], "isError": True}
    return {"content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}


def answer(message: dict[str, object]) -> dict[str, object] | None:
    method = message.get("method")
    if "id" not in message:
        return None
    params = message.get("params")
    params = params if isinstance(params, dict) else {}
    if method == "initialize":
        value: dict[str, object] = {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "toy-files", "version": "0.0.0"},
        }
    elif method == "tools/list":
        value = {"tools": TOOLS}
    elif method == "tools/call":
        arguments = params.get("arguments")
        value = call(str(params.get("name")), arguments if isinstance(arguments, dict) else {})
    elif method == "ping":
        value = {}
    else:
        return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "?"}}
    return {"jsonrpc": "2.0", "id": message["id"], "result": value}


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        reply = answer(json.loads(line))
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
