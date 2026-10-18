"""The Claude Code PreToolUse guard: default deny, fail closed, documented output."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from notary_mcp_proxy.guard import GuardPolicy, decide_hook, run_hook
from notary_mcp_proxy.jsonrpc import JsonObject

GUARD = Path(__file__).resolve().parents[1] / "examples" / "claude" / "guard.json"
POLICY_TEXT = GUARD.read_text()
POLICY = GuardPolicy.model_validate_json(POLICY_TEXT)


def _event(tool: str) -> JsonObject:
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": {"command": "ls"}}


@pytest.mark.parametrize(
    "tool",
    [
        "Bash",
        "Write",
        "Edit",
        "NotebookEdit",
        "WebFetch",
        "WebSearch",
        "Task",
        "Agent",
        "mcp__github__create_issue",
        "mcp__notary",
    ],
)
def test_default_policy_denies(tool: str) -> None:
    answer = decide_hook(_event(tool), POLICY)
    assert answer.decision == "deny"
    assert tool in answer.reason
    assert "allow" in answer.reason


@pytest.mark.parametrize(
    "tool", ["Read", "Grep", "Glob", "TodoWrite", "mcp__notary-bank__pay_bill"]
)
def test_default_policy_allows(tool: str) -> None:
    assert decide_hook(_event(tool), POLICY).decision == "allow"


@pytest.mark.parametrize(
    "stdin",
    ["", "not json", "[]", "null", "{}", '{"tool_name": 3}', '{"tool_name": ""}'],
)
def test_malformed_input_is_denied(stdin: str) -> None:
    out = json.loads(run_hook(stdin, POLICY_TEXT))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_deny_output_is_the_documented_json() -> None:
    out = json.loads(run_hook(json.dumps(_event("Bash")), POLICY_TEXT))
    assert out == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": out["hookSpecificOutput"]["permissionDecisionReason"],
        }
    }
    assert "Bash" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_allow_prints_nothing() -> None:
    assert run_hook(json.dumps(_event("Read")), POLICY_TEXT) == ""


def test_input_is_never_read() -> None:
    event: JsonObject = {"tool_name": "Bash", "tool_input": {"command": "echo harmless"}}
    assert decide_hook(event, POLICY).decision == "deny"


@pytest.mark.parametrize(
    "policy_text",
    [None, "{", "{}", '{"allow": [""], "allow_prefixes": []}', '{"allow": ["Read"]}'],
)
def test_bad_policy_denies_every_call(policy_text: str | None) -> None:
    out = json.loads(run_hook(json.dumps(_event("Read")), policy_text))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "policy" in out["hookSpecificOutput"]["permissionDecisionReason"]


def _run(stdin: str, policy: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "notary_mcp_proxy", "hook", "pre-tool-use", "--policy", str(policy)],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def test_subprocess_answers_on_stdout() -> None:
    allowed = _run(json.dumps(_event("mcp__notary-bank__read_inbox")), GUARD)
    assert (allowed.returncode, allowed.stdout, allowed.stderr) == (0, "", "")
    denied = _run(json.dumps(_event("Bash")), GUARD)
    assert denied.returncode == 2
    assert "Bash" in denied.stderr
    assert json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    garbage_run = _run("garbage", GUARD)
    assert garbage_run.returncode == 2
    assert garbage_run.stderr.strip()
    garbage = json.loads(garbage_run.stdout)
    assert garbage["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_subprocess_missing_policy_denies(tmp_path: Path) -> None:
    result = _run(json.dumps(_event("Read")), tmp_path / "missing.json")
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert result.returncode == 2
    assert "policy" in result.stderr
