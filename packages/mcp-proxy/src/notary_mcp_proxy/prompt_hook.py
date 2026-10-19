"""Claude Code `UserPromptSubmit` hook: hand what the user typed to the proxy as a trusted value.

Claude Code runs the hook as the user, before the model sees the prompt, with a JSON object on stdin
(`hook_event_name`, `prompt`, `session_id`, `transcript_path`, `cwd`, and optional `source`,
`agent_id`, ...). The hook sends `{"op": "user_prompt", "prompt": ...}` on the proxy's control
socket (`control.py`); the proxy stores it as a trusted `user` value, so an argument that quotes it
is labeled `user` instead of `llm`.

Claude Code's semantics for this event (read from the 2.1.303 binary, see docs/decisions.md): exit
0 lets the prompt through and what the hook printed on stdout may be added to the model's context;
exit 2 ERASES the user's prompt; any other exit code shows stderr to the user and goes on. So this
hook prints NOTHING on stdout, exits 0 on every path (a failed hook must not eat the user's prompt)
and puts every diagnostic on stderr, never the prompt itself. It is bounded in time: the socket
calls have a timeout and the proxy answers within a few seconds.

Only a prompt the user authored is forwarded. The `source` field says who wrote it: `user` (the
interactive composer) and `sdk` (`claude -p`, the Agent SDK) are the user's; `system`,
`loop_wakeup`, `schedule_wakeup` and `poll_event` are machine-injected turns (peer and channel
messages, task notifications) whose text can come from anywhere, so they are skipped, and so is a
prompt that comes from a subagent (`agent_id` set). A payload without `source` is forwarded (the
field is rolling out); that is stated as a limit in docs/threat-model.md.
"""

import json
from collections.abc import Callable
from pathlib import Path

from notary_mcp_proxy.approvals import printable
from notary_mcp_proxy.control import MAX_PROMPT, ControlError, encodable, find_socket, send
from notary_mcp_proxy.jsonrpc import JsonObject, as_object, as_str

HOOK_EVENT = "UserPromptSubmit"
USER_SOURCES = frozenset({"user", "sdk"})
"""`source` values that are the user's own words."""
MAX_INPUT = 4 * 1024 * 1024
"""Bytes of hook input read; a payload that does not fit is skipped, not cut."""
HOOK_TIMEOUT = 5.0
"""Seconds for connecting to the socket and for the proxy's answer (it answers within 3 s)."""

Sender = Callable[[Path, JsonObject], JsonObject]


def send_bounded(path: Path, message: JsonObject) -> JsonObject:
    """One request on the socket, with the hook's timeout for connecting and for the answer."""
    return send(path, message, timeout=HOOK_TIMEOUT)


def prompt_from(stdin_text: str) -> tuple[str | None, str]:
    """`(prompt, "")` when the hook input holds a prompt to forward, else `(None, why)`."""
    try:
        event = as_object(json.loads(stdin_text))
    except ValueError:
        event = None
    if event is None:
        return None, "the hook input is not a JSON object"
    name = as_str(event.get("hook_event_name"))
    if name is not None and name != HOOK_EVENT:
        return None, f"the hook input is a {printable(name[:40])} event, not {HOOK_EVENT}"
    prompt = as_str(event.get("prompt"))
    if prompt is None:
        return None, "the hook input has no string `prompt`"
    if "source" in event:
        source = as_str(event.get("source"))
        if source not in USER_SOURCES:
            return None, f"the prompt did not come from the user (source {printable(str(source))})"
    if event.get("agent_id") not in (None, ""):
        return None, "the prompt comes from a subagent, not from the user"
    if not prompt.strip():
        return None, "the prompt is empty"
    if not encodable(prompt):
        return None, "the prompt is not valid Unicode"
    if len(prompt) > MAX_PROMPT:
        return None, f"the prompt is longer than {MAX_PROMPT} characters; it stays untrusted"
    return prompt, ""


def forward_prompt(
    stdin_text: str, control: Path | None, *, sender: Sender = send_bounded
) -> tuple[str | None, str]:
    """Send the prompt in `stdin_text` to the proxy: `(value_id, "")` or `(None, why)`.

    `control` None means the one socket in the default directory. Never raises: every failure is
    a reason for stderr, and the prompt then simply stays untyped as far as the proxy is concerned
    (every argument stays as untrusted as it was without the hook).
    """
    prompt, why = prompt_from(stdin_text)
    if prompt is None:
        return None, why
    try:
        target = find_socket() if control is None else control
        answer = sender(target, {"op": "user_prompt", "prompt": prompt})
    except ControlError as failure:
        return None, printable(str(failure))
    if answer.get("ok") is True:
        value_id = as_str(answer.get("value_id"))
        if value_id is not None:
            return value_id, ""
        return None, "the proxy answered without a value id"
    return None, f"the proxy refused the prompt: {printable(str(answer.get('error')))}"
