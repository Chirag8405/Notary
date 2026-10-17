"""The live LLM client on the Groq SDK, plus the pure mapping to and from the SDK types.

Groq serves open models behind an OpenAI-style chat completions API. The mapping functions are
tested without a client. The SDK is imported here and nowhere in `notary_core` or `notary_world`.
This is the only module that may create a `groq.Groq` (which reads `GROQ_API_KEY` itself), and
only on first use.

The model that answers is `LlmRequest.model` (`DEFAULT_MODEL` unless a caller says otherwise), so
the model named in a recorded prompt is the one that produced the answer. Requests use
`temperature=0`; the API still does not promise identical answers, so a live run is not
reproducible and cassettes are the reproducible path.
"""

import json
import logging
import time
from collections import deque
from collections.abc import Iterable, Sequence
from typing import Protocol, cast

import groq
from groq.types.chat import (
    ChatCompletion,
    ChatCompletionAssistantMessageParam,
    ChatCompletionMessageParam,
    ChatCompletionMessageToolCall,
    ChatCompletionMessageToolCallParam,
    ChatCompletionToolParam,
)

from notary_server.llm import LlmRequest, LlmToolSpec
from notary_world.models import CassetteToolCall, CassetteTurn

RATE_LIMIT_WAITS: int = 60
"""How many times one request waits out a 429 (the free tier allows few tokens per minute and per
day, and frees them gradually). It never retries a bad answer."""
MAX_WAIT_SECONDS: float = 900.0


LOG = logging.getLogger(__name__)


class GroqResponseError(ValueError):
    """The model answered with something the runner cannot use (no choice, bad tool arguments)."""


class ChatApi(Protocol):
    """The one SDK call used, so tests can pass a fake."""

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        temperature: float,
        messages: Iterable[ChatCompletionMessageParam],
        tools: Iterable[ChatCompletionToolParam],
    ) -> ChatCompletion: ...


class _SdkChat:
    def __init__(self) -> None:
        self._client = groq.Groq()

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        temperature: float,
        messages: Iterable[ChatCompletionMessageParam],
        tools: Iterable[ChatCompletionToolParam],
    ) -> ChatCompletion:
        tool_list = list(tools)
        for attempt in range(RATE_LIMIT_WAITS + 1):
            try:
                return self._client.chat.completions.create(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    messages=messages,
                    tools=tool_list if tool_list else groq.omit,
                    # Reasoning tokens count against `max_tokens`; a long think must not leave
                    # no answer.
                    reasoning_effort="low" if model.startswith("openai/gpt-oss") else groq.omit,
                )
            except groq.RateLimitError as limited:
                if attempt == RATE_LIMIT_WAITS:
                    raise
                wait = retry_after(limited)
                LOG.warning("Groq rate limit; waiting %.0fs (attempt %d)", wait, attempt + 1)
                time.sleep(wait)
        raise AssertionError("unreachable")


def retry_after(error: groq.RateLimitError) -> float:
    """Seconds to wait: the `retry-after` header, else one second more than a minute's refill."""
    raw = error.response.headers.get("retry-after")
    try:
        seconds = float(raw) if raw is not None else 30.0
    except ValueError:
        seconds = 30.0
    return min(max(seconds, 1.0) + 1.0, MAX_WAIT_SECONDS)


def _tool_id(number: int) -> str:
    return f"call_{number}"


def _arguments(args: dict[str, str]) -> str:
    return json.dumps(args, sort_keys=True, separators=(",", ":"))


def to_groq_messages(
    system: str, turns: Sequence[CassetteTurn]
) -> list[ChatCompletionMessageParam]:
    """The system prompt and the turns as SDK messages.

    Tool call number `n` (1-based over the whole list) gets the id `call_<n>`. Each tool turn
    answers the oldest tool call that is still open, first in first out.
    """
    messages: list[ChatCompletionMessageParam] = [{"role": "system", "content": system}]
    open_ids: deque[str] = deque()
    counter = 0
    for turn in turns:
        if turn.role == "tool":
            if not open_ids:
                raise ValueError("tool turn without a tool call")
            messages.append(
                {"role": "tool", "tool_call_id": open_ids.popleft(), "content": turn.content}
            )
            continue
        if open_ids:
            raise ValueError("tool call without a result")
        if turn.role == "user":
            messages.append({"role": "user", "content": turn.content})
            continue
        if not turn.content and not turn.tool_calls:
            raise ValueError("empty assistant turn")
        assistant: ChatCompletionAssistantMessageParam = {"role": "assistant"}
        if turn.content:
            assistant["content"] = turn.content
        calls: list[ChatCompletionMessageToolCallParam] = []
        for call in turn.tool_calls:
            counter += 1
            open_ids.append(_tool_id(counter))
            calls.append(
                {
                    "id": _tool_id(counter),
                    "type": "function",
                    "function": {"name": call.tool, "arguments": _arguments(call.args)},
                }
            )
        if calls:
            assistant["tool_calls"] = calls
        messages.append(assistant)
    if open_ids:
        raise ValueError("tool call without a result")
    return messages


def _call_args(call: ChatCompletionMessageToolCall) -> dict[str, str]:
    try:
        parsed: object = json.loads(call.function.arguments or "{}")
    except json.JSONDecodeError:
        raise GroqResponseError("tool arguments are not JSON") from None
    if not isinstance(parsed, dict):
        raise GroqResponseError("tool arguments are not a JSON object")
    return {
        str(key): value
        if isinstance(value, str)
        else json.dumps(value, sort_keys=True, separators=(",", ":"))
        for key, value in cast(dict[object, object], parsed).items()
    }


def from_groq_completion(completion: ChatCompletion) -> CassetteTurn:
    """The assistant turn for an SDK answer: its text and its tool calls in order."""
    if not completion.choices:
        raise GroqResponseError("no choice in the answer")
    message = completion.choices[0].message
    calls = tuple(
        CassetteToolCall(tool=call.function.name, args=_call_args(call))
        for call in message.tool_calls or ()
    )
    return CassetteTurn(role="assistant", content=message.content or "", tool_calls=calls)


def _tool_param(spec: LlmToolSpec) -> ChatCompletionToolParam:
    schema = json.loads(spec.input_schema)
    if not isinstance(schema, dict):
        raise ValueError("input_schema must be a JSON object")
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": cast(dict[str, object], schema),
        },
    }


class GroqClient:
    """Live client: one chat completion per request, no retries, no streaming."""

    def __init__(self, *, chat_api: ChatApi | None = None) -> None:
        self._api = chat_api

    def _chat(self) -> ChatApi:
        if self._api is None:
            self._api = _SdkChat()
        return self._api

    def complete(self, request: LlmRequest) -> CassetteTurn:
        completion = self._chat().create(
            model=request.model,
            max_tokens=request.max_tokens,
            temperature=0,
            messages=to_groq_messages(request.system, request.messages),
            tools=[_tool_param(spec) for spec in request.tools],
        )
        return from_groq_completion(completion)
