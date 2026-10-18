"""A scriptable stdlib-only MCP server (stdio) for tests: `python fake_server.py SCRIPT.json`.

Script keys: `tools` (the tool list), `after_lists` (`{"3": {"tools": [...]}}` replaces the list
from the 3rd `tools/list` on, a rug pull), `results` (`{tool: {"content": [...], "isError": ...}}`),
`behaviors` (`{tool: "hang" | "exit" | "error" | "rpc_error" | "late"}`), `swap_after_call`
(`{tool: {"tools": [...]}}`: when that tool is called the server switches to the new tool list and
sends `notifications/tools/list_changed` before it answers).

Behaviors: `hang` never answers that call or any later request (it keeps reading, so it sees
`notifications/cancelled`, and it exits at EOF); `exit` dies; `error` answers `isError: true`;
`rpc_error` answers a JSON-RPC error whose message is `evil`; `late` holds its answer back and
sends it just before the answer to the next request (a late answer, with no sleeping).

Every request and every `notifications/cancelled` is appended as a JSON line to
`<script>.calls.jsonl`.
"""

import json
import sys
from pathlib import Path

script_path = Path(sys.argv[1])
script = json.loads(script_path.read_text())
log_path = script_path.with_name(script_path.name + ".calls.jsonl")
lists_seen = 0
hung = False
held: list[dict[str, object]] = []
swapped: list[list[object]] = []


def log(entry: dict[str, object]) -> None:
    with log_path.open("a", encoding="utf-8") as out:
        out.write(json.dumps(entry) + "\n")


def current_tools() -> list[object]:
    if swapped:
        return swapped[-1]
    tools = script.get("tools", [])
    replacements = sorted(script.get("after_lists", {}).items(), key=lambda item: int(item[0]))
    for start, replacement in replacements:
        if lists_seen >= int(start):
            tools = replacement["tools"]
    return tools


def send(message: dict[str, object]) -> None:
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", **message}) + "\n")
    sys.stdout.flush()


def reply(request_id: object, result: object) -> None:
    send({"id": request_id, "result": result})


def call(name: str, request_id: object) -> None:
    """Handle one call."""
    global hung
    behavior = script.get("behaviors", {}).get(name)
    if behavior == "hang":
        hung = True
        return
    if behavior == "exit":
        sys.exit(1)
    if behavior == "rpc_error":
        send({"id": request_id, "error": {"code": -32000, "message": "evil"}})
        return
    if behavior == "late":
        held.append({"id": request_id, "result": script.get("results", {}).get(name, ok(name))})
        return
    if behavior == "error":
        reply(
            request_id, {"content": [{"type": "text", "text": f"{name} failed"}], "isError": True}
        )
        return
    replacement = script.get("swap_after_call", {}).get(name)
    if replacement is not None:
        swapped.append(replacement["tools"])
        send({"method": "notifications/tools/list_changed"})
    reply(request_id, script.get("results", {}).get(name, ok(name)))


def ok(name: str) -> dict[str, object]:
    return {"content": [{"type": "text", "text": f"{name} ok"}], "isError": False}


for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")
    if "id" not in message:
        if method == "notifications/cancelled":
            log({"method": method, "requestId": message["params"]["requestId"]})
        continue
    if hung:
        continue
    while held:
        send(held.pop(0))
    if method == "initialize":
        reply(
            message["id"],
            {
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "0"},
            },
        )
    elif method == "tools/list":
        lists_seen += 1
        log({"method": "tools/list"})
        reply(message["id"], {"tools": current_tools()})
    elif method == "tools/call":
        params = message["params"]
        log(
            {
                "method": "tools/call",
                "id": message["id"],
                "name": params["name"],
                "arguments": params.get("arguments"),
            }
        )
        call(params["name"], message["id"])
    else:
        reply(message["id"], {})
