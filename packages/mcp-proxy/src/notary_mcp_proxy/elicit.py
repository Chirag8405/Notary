"""Ask the user to approve an escalated call through MCP elicitation (spec 2025-06-18).

The client shows the request to the USER in its own UI, so the answer does not come from the
model. The request asks for one thing only, an enum `decision` of approve or reject: no free text
and nothing secret. The message holds the tool name, the label-rendered card (built from labels
only, made printable) and fixed text. The card's previews quote values an attacker may have
written, which is why the message ends with a fixed warning.

Fail closed: only `action == "accept"` with `content.decision == "approve"` approves. Every other
answer, in every shape, is a rejection.
"""

from pydantic import JsonValue

from notary_mcp_proxy.approvals import Choice, Pending, printable
from notary_mcp_proxy.jsonrpc import JsonObject, as_object

METHOD = "elicitation/create"
DECISION = "decision"
WARNING = "Approve only if you asked for this."


def supports_form(capabilities: JsonValue) -> bool:
    """Whether the client's `initialize` capabilities declare form elicitation.

    `"elicitation": {}` means form mode (2025-06-18); newer clients write the modes out
    (`{"form": {}, "url": {}}`). A client that declares only `url` cannot show our form.
    """
    caps = as_object(capabilities) or {}
    declared = as_object(caps.get("elicitation"))
    if declared is None:
        return False
    return not declared or "form" in declared


def approval_request(pending: Pending) -> JsonObject:
    """The `elicitation/create` params for one open card."""
    message = (
        f"NOTARY: {printable(pending.tool)} needs your approval.\n{pending.card_text}\n{WARNING}"
    )
    return {
        "message": message,
        "requestedSchema": {
            "type": "object",
            "properties": {
                DECISION: {
                    "type": "string",
                    "enum": ["approve", "reject"],
                    "title": "Decision",
                }
            },
            "required": [DECISION],
        },
    }


def parse_answer(result: JsonObject) -> Choice:
    """Approve only for an explicit accept with `decision == "approve"`; reject otherwise."""
    if result.get("action") != "accept":
        return "reject"
    content = as_object(result.get("content"))
    if content is None or content.get(DECISION) != "approve":
        return "reject"
    return "approve"
