"""A scriptable stdlib-only MCP server (stdio) for tests: `python fake_server.py SCRIPT.json`.

Script keys: `tools` (the tool list), `after_lists` (`{"3": {"tools": [...]}}` replaces the list
from the 3rd `tools/list` on, a rug pull), `results` (`{tool: {"content": [...], "isError": ...}}`),
`behaviors` (`{tool: "hang" | "exit" | "error"}`). Every request is appended as a JSON line to
`<script>.calls.jsonl`.
"""

import json
import sys
import time
from pathlib import Path

script_path = Path(sys.argv[1])
script = json.loads(script_path.read_text())
log_path = script_path.with_name(script_path.name + ".calls.jsonl")
lists_seen = 0


def log(entry: dict[str, object]) -> None:
    with log_path.open("a", encoding="utf-8") as out:
        out.write(json.dumps(entry) + "\n")


def current_tools() -> list[object]:
    tools = script.get("tools", [])
    replacements = sorted(script.get("after_lists", {}).items(), key=lambda item: int(item[0]))
    for start, replacement in replacements:
        if lists_seen >= int(start):
            tools = replacement["tools"]
    return tools


def reply(request_id: object, result: object) -> None:
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n")
    sys.stdout.flush()


def call(name: str) -> dict[str, object]:
    behavior = script.get("behaviors", {}).get(name)
    if behavior == "hang":
        while True:
            time.sleep(3600)
    if behavior == "exit":
        sys.exit(1)
    if behavior == "error":
        return {"content": [{"type": "text", "text": f"{name} failed"}], "isError": True}
    default = {"content": [{"type": "text", "text": f"{name} ok"}], "isError": False}
    return script.get("results", {}).get(name, default)


for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")
    if "id" not in message:
        continue
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
        log({"method": "tools/call", "name": params["name"], "arguments": params.get("arguments")})
        reply(message["id"], call(params["name"]))
    else:
        reply(message["id"], {})
