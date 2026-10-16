import os
from collections.abc import Iterable, Mapping

import pytest
from anthropic.types import ContentBlock, Message, MessageParam, TextBlock, ToolParam, ToolUseBlock

from notary_server.anthropic_client import (
    AnthropicClient,
    from_anthropic_content,
    to_anthropic_messages,
)
from notary_server.llm import DEFAULT_MODEL, LlmRequest, LlmToolSpec
from notary_world.models import CassetteToolCall, CassetteTurn


def turn(role: str, content: str, *calls: tuple[str, dict[str, str]]) -> CassetteTurn:
    return CassetteTurn(
        role="user" if role == "user" else "assistant" if role == "assistant" else "tool",
        content=content,
        tool_calls=tuple(CassetteToolCall(tool=t, args=a) for t, a in calls),
    )


def text_block(text: str) -> TextBlock:
    return TextBlock(type="text", text=text, citations=None)


def tool_use(name: str, **fields: object) -> ToolUseBlock:
    return ToolUseBlock.model_construct(type="tool_use", id="x", name=name, input=dict(fields))


def message(blocks: list[ContentBlock]) -> Message:
    return Message.model_construct(content=blocks)


class FakeApi:
    def __init__(self, answer: Message | Exception) -> None:
        self.answer = answer
        self.calls: list[Mapping[str, object]] = []

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: Iterable[MessageParam],
        tools: Iterable[ToolParam],
    ) -> Message:
        self.calls.append(
            {
                "model": model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": list(messages),
                "tools": list(tools),
            }
        )
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


WORKED_EXAMPLE = [
    turn("user", "Pay my December bill"),
    turn("assistant", "", ("read_inbox", {})),
    turn("tool", "sender: billing"),
    turn(
        "assistant",
        "Paying.",
        ("pay_bill", {"payee": "DE00ACME00000000000001", "amount": "120.00"}),
    ),
    turn("tool", "paid"),
]


@pytest.mark.invariant("I6")
def test_message_mapping_worked_example() -> None:
    assert to_anthropic_messages(WORKED_EXAMPLE) == [
        {"role": "user", "content": "Pay my December bill"},
        {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": "toolu_1", "name": "read_inbox", "input": {}}],
        },
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1", "content": "sender: billing"}
            ],
        },
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Paying."},
                {
                    "type": "tool_use",
                    "id": "toolu_2",
                    "name": "pay_bill",
                    "input": {"payee": "DE00ACME00000000000001", "amount": "120.00"},
                },
            ],
        },
        {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "toolu_2", "content": "paid"}],
        },
    ]


@pytest.mark.invariant("I6")
def test_consecutive_tool_turns_merge_fifo() -> None:
    turns = [
        turn("user", "go"),
        turn("assistant", "", ("read_inbox", {}), ("read_calendar", {})),
        turn("tool", "mail"),
        turn("tool", "events"),
    ]
    messages = to_anthropic_messages(turns)
    assert len(messages) == 3
    assert messages[2] == {
        "role": "user",
        "content": [
            {"type": "tool_result", "tool_use_id": "toolu_1", "content": "mail"},
            {"type": "tool_result", "tool_use_id": "toolu_2", "content": "events"},
        ],
    }


@pytest.mark.invariant("I6")
def test_tool_turn_without_call_is_rejected() -> None:
    with pytest.raises(ValueError, match="tool turn without a tool call"):
        to_anthropic_messages([turn("user", "x"), turn("tool", "orphan")])


@pytest.mark.invariant("I6")
def test_unanswered_tool_call_is_rejected() -> None:
    with pytest.raises(ValueError, match="tool call without a result"):
        to_anthropic_messages([turn("user", "x"), turn("assistant", "", ("read_inbox", {}))])
    with pytest.raises(ValueError, match="tool call without a result"):
        to_anthropic_messages(
            [
                turn("user", "x"),
                turn("assistant", "", ("read_inbox", {})),
                turn("user", "interrupt"),
            ]
        )


@pytest.mark.invariant("I6")
def test_empty_assistant_turn_is_rejected() -> None:
    with pytest.raises(ValueError, match="empty assistant turn"):
        to_anthropic_messages([turn("user", "x"), turn("assistant", "")])


@pytest.mark.invariant("I6")
def test_response_mapping() -> None:
    blocks: list[ContentBlock] = [
        text_block("Looking. "),
        tool_use("pay_bill", payee="DE00", amount=120, note={"b": 1, "a": [1, 2]}),
        text_block("Done."),
    ]
    result = from_anthropic_content(blocks)
    assert result.role == "assistant"
    assert result.content == "Looking. Done."
    assert result.tool_calls == (
        CassetteToolCall(
            tool="pay_bill",
            args={"payee": "DE00", "amount": "120", "note": '{"a":[1,2],"b":1}'},
        ),
    )


@pytest.mark.invariant("I6")
def test_client_calls_the_api_with_the_request() -> None:
    api = FakeApi(message([text_block("hello")]))
    client = AnthropicClient(messages_api=api)
    request = LlmRequest(
        model=DEFAULT_MODEL,
        system="sys",
        messages=(turn("user", "hi"),),
        tools=(
            LlmToolSpec(
                name="read_inbox",
                description="List mail.",
                input_schema='{"properties":{},"required":[],"type":"object"}',
            ),
        ),
        max_tokens=77,
    )
    answer = client.complete(request)
    assert answer == from_anthropic_content([text_block("hello")])
    (call,) = api.calls
    assert call["model"] == DEFAULT_MODEL
    assert call["max_tokens"] == 77
    assert call["system"] == "sys"
    assert call["messages"] == [{"role": "user", "content": "hi"}]
    assert call["tools"] == [
        {
            "name": "read_inbox",
            "description": "List mail.",
            "input_schema": {"properties": {}, "required": [], "type": "object"},
        }
    ]


@pytest.mark.invariant("I6")
def test_no_sampling_parameters_are_sent() -> None:
    api = FakeApi(message([text_block("x")]))
    AnthropicClient(messages_api=api).complete(
        LlmRequest(
            model=DEFAULT_MODEL, system="s", messages=(turn("user", "hi"),), tools=(), max_tokens=5
        )
    )
    assert set(api.calls[0]) == {"model", "max_tokens", "system", "messages", "tools"}


@pytest.mark.invariant("I6")
def test_bad_tool_schema_is_rejected() -> None:
    client = AnthropicClient(messages_api=FakeApi(message([text_block("x")])))
    request = LlmRequest(
        model=DEFAULT_MODEL,
        system="s",
        messages=(turn("user", "hi"),),
        tools=(LlmToolSpec(name="t", description="d", input_schema="[1, 2]"),),
        max_tokens=5,
    )
    with pytest.raises(ValueError, match="input_schema must be a JSON object"):
        client.complete(request)


@pytest.mark.invariant("I6")
def test_sdk_errors_propagate() -> None:
    client = AnthropicClient(messages_api=FakeApi(RuntimeError("boom")))
    request = LlmRequest(
        model=DEFAULT_MODEL, system="s", messages=(turn("user", "hi"),), tools=(), max_tokens=5
    )
    with pytest.raises(RuntimeError, match="boom"):
        client.complete(request)


class ExplodingEnviron(dict[str, str]):
    def __getitem__(self, key: str) -> str:
        raise AssertionError("environment was read")

    def get(self, key: str, default: object = None) -> str:
        raise AssertionError("environment was read")


@pytest.mark.invariant("I6")
def test_injected_api_never_touches_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "environ", ExplodingEnviron())
    api = FakeApi(message([text_block("x")]))
    request = LlmRequest(
        model=DEFAULT_MODEL, system="s", messages=(turn("user", "hi"),), tools=(), max_tokens=5
    )
    assert AnthropicClient(messages_api=api).complete(request).content == "x"
