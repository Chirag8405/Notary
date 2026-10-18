"""Claude Code `PreToolUse` guard: only an explicit list of tools may run.

The hook never reads a tool's input. Anything not allowed, and anything it cannot
understand, is denied (it never fails open). Allowing prints nothing, so Claude Code's
normal permission prompts still apply.
"""

import json
from typing import Literal

from pydantic import JsonValue, field_validator

from notary_core.models import NotaryModel
from notary_mcp_proxy.jsonrpc import JsonObject, as_object, as_str


class GuardPolicy(NotaryModel):
    allow: tuple[str, ...]
    allow_prefixes: tuple[str, ...]

    @field_validator("allow", "allow_prefixes")
    @classmethod
    def _no_empty(cls, names: tuple[str, ...]) -> tuple[str, ...]:
        if any(not name for name in names):
            raise ValueError("an empty tool name or prefix would allow everything")
        return names


class HookAnswer(NotaryModel):
    decision: Literal["allow", "deny"]
    reason: str


def _deny(reason: str) -> HookAnswer:
    return HookAnswer(decision="deny", reason=reason)


def decide_hook(event: JsonObject, policy: GuardPolicy) -> HookAnswer:
    """Pure: allow only a tool named in `policy`; deny a malformed event."""
    tool = as_str(event.get("tool_name"))
    if not tool:
        return _deny("NOTARY guard: the hook event has no string `tool_name`; denied")
    if tool in policy.allow or any(tool.startswith(prefix) for prefix in policy.allow_prefixes):
        return HookAnswer(decision="allow", reason=f"{tool} is allowed by the guard policy")
    return _deny(
        f"NOTARY guard: {tool} is not on the allow list, so it is denied (every effect must go "
        f"through NOTARY tools). To allow it, add it to `allow` or a prefix to `allow_prefixes` "
        f"in the guard policy."
    )


def hook_output(answer: HookAnswer) -> str:
    """What the hook prints: nothing for allow, the documented deny JSON otherwise."""
    if answer.decision == "allow":
        return ""
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": answer.reason,
            }
        }
    )


def run_hook(stdin_text: str, policy_text: str | None) -> str:
    """Stdin and policy file text in, stdout text out. Any failure is a deny."""
    try:
        if policy_text is None:
            return hook_output(_deny("NOTARY guard: the policy file could not be read; denied"))
        try:
            policy = GuardPolicy.model_validate_json(policy_text)
        except ValueError as error:
            return hook_output(
                _deny(f"NOTARY guard: the policy file does not parse ({error}); every call denied")
            )
        try:
            parsed: JsonValue = json.loads(stdin_text)
        except ValueError:
            return hook_output(_deny("NOTARY guard: the hook input is not JSON; denied"))
        event = as_object(parsed)
        if event is None:
            return hook_output(_deny("NOTARY guard: the hook input is not a JSON object; denied"))
        return hook_output(decide_hook(event, policy))
    except Exception as error:
        return hook_output(_deny(f"NOTARY guard: internal error ({type(error).__name__}); denied"))
