"""The Groq client: pure mappings and the single SDK call, with a fake API (no network)."""

import os
from collections.abc import Iterable, Mapping

import groq
import httpx
import pytest
from groq.types.chat import (
    ChatCompletion,
    ChatCompletionMessage,
    ChatCompletionMessageParam,
    ChatCompletionMessageToolCall,
    ChatCompletionToolParam,
)

from notary_server.groq_client import (
    GroqClient,
    GroqResponseError,
    from_groq_completion,
    retry_after,
    to_groq_messages,
)
from notary_server.llm import DEFAULT_MODEL, LlmRequest, LlmToolSpec
from notary_world.models import CassetteToolCall, CassetteTurn


def turn(role: str, content: str, *calls: tuple[str, dict[str, str]]) -> CassetteTurn:
    return CassetteTurn(
        role="user" if role == "user" else "assistant" if role == "assistant" else "tool",
        content=content,
        tool_calls=tuple(CassetteToolCall(tool=t, args=a) for t, a in calls),
    )


def tool_call(name: str, arguments: str) -> ChatCompletionMessageToolCall:
    return ChatCompletionMessageToolCall.model_validate(
        {"id": "x", "type": "function", "function": {"name": name, "arguments": arguments}}
    )


def completion(
    content: str | None, *calls: ChatCompletionMessageToolCall, choices: bool = True
) -> ChatCompletion:
    message = ChatCompletionMessage.model_construct(
        role="assistant", content=content, tool_calls=list(calls) or None
    )
    return ChatCompletion.model_construct(
        choices=[type("Choice", (), {"message": message})()] if choices else []
    )


class FakeApi:
    def __init__(self, answer: ChatCompletion | Exception) -> None:
        self.answer = answer
        self.calls: list[Mapping[str, object]] = []

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        temperature: float,
        messages: Iterable[ChatCompletionMessageParam],
        tools: Iterable[ChatCompletionToolParam],
    ) -> ChatCompletion:
        self.calls.append(
            {
                "model": model,
                "max_tokens": max_tokens,
                "temperature": temperature,
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


def request(*turns: CassetteTurn, tools: tuple[LlmToolSpec, ...] = ()) -> LlmRequest:
    return LlmRequest(model=DEFAULT_MODEL, system="sys", messages=turns, tools=tools, max_tokens=5)


@pytest.mark.invariant("I6")
def test_message_mapping_worked_example() -> None:
    assert to_groq_messages("sys", WORKED_EXAMPLE) == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "Pay my December bill"},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_inbox", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": "sender: billing"},
        {
            "role": "assistant",
            "content": "Paying.",
            "tool_calls": [
                {
                    "id": "call_2",
                    "type": "function",
                    "function": {
                        "name": "pay_bill",
                        "arguments": '{"amount":"120.00","payee":"DE00ACME00000000000001"}',
                    },
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call_2", "content": "paid"},
    ]


@pytest.mark.invariant("I6")
def test_tool_results_match_open_calls_first_in_first_out() -> None:
    turns = [
        turn("user", "go"),
        turn("assistant", "", ("read_inbox", {}), ("read_calendar", {})),
        turn("tool", "mail"),
        turn("tool", "events"),
    ]
    messages = to_groq_messages("sys", turns)
    assert [m.get("tool_call_id") for m in messages[3:]] == ["call_1", "call_2"]


@pytest.mark.invariant("I6")
@pytest.mark.parametrize(
    ("turns", "message"),
    [
        ([turn("tool", "x")], "tool turn without a tool call"),
        ([turn("assistant", "", ("a", {}))], "tool call without a result"),
        (
            [turn("assistant", "", ("a", {})), turn("user", "hi")],
            "tool call without a result",
        ),
        ([turn("assistant", "")], "empty assistant turn"),
    ],
)
def test_invalid_turn_lists_are_refused(turns: list[CassetteTurn], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        to_groq_messages("sys", turns)


@pytest.mark.invariant("I6")
def test_answer_text_and_calls_in_order() -> None:
    answer = completion(
        "Paying.",
        tool_call("read_inbox", "{}"),
        tool_call("pay_bill", '{"payee": "DE00X", "amount": 12, "note": null}'),
    )
    assert from_groq_completion(answer) == CassetteTurn(
        role="assistant",
        content="Paying.",
        tool_calls=(
            CassetteToolCall(tool="read_inbox", args={}),
            CassetteToolCall(
                tool="pay_bill", args={"payee": "DE00X", "amount": "12", "note": "null"}
            ),
        ),
    )
    assert from_groq_completion(completion(None)).content == ""
    assert (
        from_groq_completion(completion("x", tool_call("read_inbox", ""))).tool_calls[0].args == {}
    )


@pytest.mark.invariant("I6")
@pytest.mark.parametrize("arguments", ["{not json", "[1, 2]", '"text"'])
def test_bad_tool_arguments_are_an_error(arguments: str) -> None:
    with pytest.raises(GroqResponseError):
        from_groq_completion(completion("", tool_call("pay_bill", arguments)))


@pytest.mark.invariant("I6")
def test_no_choice_is_an_error() -> None:
    with pytest.raises(GroqResponseError, match="no choice"):
        from_groq_completion(completion("x", choices=False))


@pytest.mark.invariant("I6")
def test_client_sends_the_prompts_model_and_zero_temperature() -> None:
    api = FakeApi(completion("ok"))
    spec = LlmToolSpec(name="read_inbox", description="Read mail", input_schema='{"type":"object"}')
    client = GroqClient(chat_api=api)
    assert client.complete(request(turn("user", "hi"), tools=(spec,))).content == "ok"
    (call,) = api.calls
    assert call["model"] == DEFAULT_MODEL  # the model the prompt names answers it
    assert (call["max_tokens"], call["temperature"]) == (5, 0)
    assert call["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
    ]
    assert call["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "read_inbox",
                "description": "Read mail",
                "parameters": {"type": "object"},
            },
        }
    ]


@pytest.mark.invariant("I6")
def test_bad_tool_schema_is_rejected() -> None:
    spec = LlmToolSpec(name="t", description="d", input_schema="[1]")
    client = GroqClient(chat_api=FakeApi(completion("x")))
    with pytest.raises(ValueError, match="input_schema must be a JSON object"):
        client.complete(request(turn("user", "hi"), tools=(spec,)))


@pytest.mark.invariant("I6")
def test_sdk_errors_propagate() -> None:
    client = GroqClient(chat_api=FakeApi(RuntimeError("boom")))
    with pytest.raises(RuntimeError, match="boom"):
        client.complete(request(turn("user", "hi")))


class ExplodingEnviron(dict[str, str]):
    def __getitem__(self, key: str) -> str:
        raise AssertionError("environment was read")

    def get(self, key: str, default: object = None) -> str:
        raise AssertionError("environment was read")


@pytest.mark.invariant("I6")
def test_injected_api_never_touches_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "environ", ExplodingEnviron())
    client = GroqClient(chat_api=FakeApi(completion("x")))
    assert client.complete(request(turn("user", "hi"))).content == "x"


def rate_limited(retry_after: str | None) -> groq.RateLimitError:
    headers = {} if retry_after is None else {"retry-after": retry_after}
    response = httpx.Response(
        429, headers=headers, request=httpx.Request("POST", "https://api.groq.test/chat")
    )
    return groq.RateLimitError("limit", response=response, body=None)


@pytest.mark.invariant("I6")
@pytest.mark.parametrize(
    ("header", "seconds"),
    [("12", 13.0), ("0", 2.0), (None, 31.0), ("soon", 31.0), ("99999", 900.0)],
)
def test_rate_limit_wait_follows_retry_after(header: str | None, seconds: float) -> None:
    assert retry_after(rate_limited(header)) == seconds
