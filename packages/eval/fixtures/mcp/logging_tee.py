"""Run a real MCP server and write every tool call it receives to a log (stdlib only).

    python logging_tee.py LOG -- COMMAND [ARG ...]

MCP over stdio is one JSON message per line. This script starts COMMAND, copies its own stdin to
the child's stdin and the child's stdout to its own stdout, unchanged, and appends one line
`{"tool": ..., "arguments": ...}` to LOG for each `tools/call` request it forwards. The eval judges
a task on that log (what reached the server), so a server that keeps no log of its own can be
measured the same way as the fake one. It never changes, delays or drops a message.
"""

import contextlib
import json
import shutil
import subprocess
import sys
import threading


def _log_call(log_path: str, line: str) -> None:
    try:
        message = json.loads(line)
    except ValueError:
        return
    if not isinstance(message, dict) or message.get("method") != "tools/call":
        return
    params = message.get("params")
    if not isinstance(params, dict):
        return
    arguments = params.get("arguments")
    entry = {
        "tool": params.get("name"),
        "arguments": arguments if isinstance(arguments, dict) else {},
    }
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(json.dumps(entry) + "\n")


def _copy_requests(child: subprocess.Popen[bytes], log_path: str) -> None:
    assert child.stdin is not None
    try:
        for raw in sys.stdin.buffer:
            _log_call(log_path, raw.decode("utf-8", "replace"))
            child.stdin.write(raw)
            child.stdin.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        with contextlib.suppress(OSError):
            child.stdin.close()


def main(argv: list[str]) -> int:
    if len(argv) < 4 or argv[2] != "--":
        print("usage: logging_tee.py LOG -- COMMAND [ARG ...]", file=sys.stderr)
        return 2
    log_path, command = argv[1], argv[3:]
    command[0] = shutil.which(command[0]) or command[0]
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    threading.Thread(target=_copy_requests, args=(child, log_path), daemon=True).start()
    assert child.stdout is not None
    for raw in child.stdout:
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
    return child.wait()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
