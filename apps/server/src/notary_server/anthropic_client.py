"""The live LLM client on the raw Anthropic SDK, plus the pure mapping to and from the SDK types.

The mapping functions are tested without a client. The SDK is imported here and nowhere in
`notary_core` or `notary_world`. This is the only module that may create an `anthropic.Anthropic`
(which reads `ANTHROPIC_API_KEY` itself), and only on first use. The current SDK exposes no
sampling parameters on `messages.create`, so none is sent; a live run is therefore not
reproducible, and cassettes are the reproducible path.
"""

import json
from collections import deque
from collections.abc import Iterable, Sequence
from typing import Protocol, cast

import anthropic
from anthropic.types import (
    ContentBlock,
    Message,
    MessageParam,
    TextBlock,
    TextBlockParam,
    ToolParam,
    ToolResultBlockParam,
    ToolUseBlock,
    ToolUseBlockParam,
)

from notary_server.llm import LlmRequest, LlmToolSpec
from notary_world.models import CassetteToolCall, CassetteTurn


class MessagesApi(Protocol):
    """The one SDK call used, so tests can pass a fake."""

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: Iterable[MessageParam],
        tools: Iterable[ToolParam],
    ) -> Message: ...


class _SdkMessages:
    def __init__(self) -> None:
        self._client = anthropic.Anthropic()

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: Iterable[MessageParam],
        tools: Iterable[ToolParam],
    ) -> Message:
        return self._client.messages.create(
            model=model, max_tokens=max_tokens, system=system, messages=messages, tools=tools
        )


def _tool_id(number: int) -> str:
    return f"toolu_{number}"


def to_anthropic_messages(turns: Sequence[CassetteTurn]) -> list[MessageParam]:
    """User, assistant and tool turns as SDK messages.

    Tool call number `n` (1-based over the whole list) gets the id `toolu_<n>`. Consecutive tool
    turns become one user message of `tool_result` blocks, matched first-in first-out to the
    tool calls that are still open.
    """
    messages: list[MessageParam] = []
    results: list[ToolResultBlockParam] = []
    open_ids: deque[str] = deque()
    counter = 0

    def flush() -> None:
        if open_ids:
            raise ValueError("tool call without a result")
        if results:
            messages.append({"role": "user", "content": list(results)})
            results.clear()

    for turn in turns:
        if turn.role == "tool":
            if not open_ids:
                raise ValueError("tool turn without a tool call")
            results.append(
                {"type": "tool_result", "tool_use_id": open_ids.popleft(), "content": turn.content}
            )
            continue
        flush()
        if turn.role == "user":
            messages.append({"role": "user", "content": turn.content})
            continue
        blocks: list[TextBlockParam | ToolUseBlockParam] = []
        if turn.content:
            blocks.append({"type": "text", "text": turn.content})
        for call in turn.tool_calls:
            counter += 1
            open_ids.append(_tool_id(counter))
            arguments: dict[str, object] = dict(call.args)
            blocks.append(
                {"type": "tool_use", "id": _tool_id(counter), "name": call.tool, "input": arguments}
            )
        if not blocks:
            raise ValueError("empty assistant turn")
        messages.append({"role": "assistant", "content": blocks})
    flush()
    return messages


def from_anthropic_content(blocks: Sequence[ContentBlock]) -> CassetteTurn:
    """The assistant turn for an SDK answer: its text joined, its tool uses in order."""
    texts: list[str] = []
    calls: list[CassetteToolCall] = []
    for block in blocks:
        if isinstance(block, TextBlock):
            texts.append(block.text)
        elif isinstance(block, ToolUseBlock):
            args = {
                key: value
                if isinstance(value, str)
                else json.dumps(value, sort_keys=True, separators=(",", ":"))
                for key, value in block.input.items()
            }
            calls.append(CassetteToolCall(tool=block.name, args=args))
    return CassetteTurn(role="assistant", content="".join(texts), tool_calls=tuple(calls))


def _tool_param(spec: LlmToolSpec) -> ToolParam:
    schema = json.loads(spec.input_schema)
    if not isinstance(schema, dict):
        raise ValueError("input_schema must be a JSON object")
    return {
        "name": spec.name,
        "description": spec.description,
        "input_schema": cast(dict[str, object], schema),
    }


class AnthropicClient:
    """Live client: one `messages.create` call per request, no retries, no streaming."""

    def __init__(self, *, messages_api: MessagesApi | None = None) -> None:
        self._api = messages_api

    def _messages(self) -> MessagesApi:
        if self._api is None:
            self._api = _SdkMessages()
        return self._api

    def complete(self, request: LlmRequest) -> CassetteTurn:
        message = self._messages().create(
            model=request.model,
            max_tokens=request.max_tokens,
            system=request.system,
            messages=to_anthropic_messages(request.messages),
            tools=[_tool_param(spec) for spec in request.tools],
        )
        return from_anthropic_content(message.content)
