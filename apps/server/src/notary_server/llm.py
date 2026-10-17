"""LLM access for the server: one narrow interface and three ways to answer it.

`LlmClient` is all the compiler, the agent runner and the arena know. `CassetteClient` answers
only from a recorded cassette (keyed by lane and the exact prompt), so the stage run replays
byte for byte without a network; `RecordingClient` wraps another client and writes such a
cassette; `ScriptedClient` is the test double. Nothing here reads the clock, the environment or
the network.
"""

from collections.abc import Sequence
from typing import Protocol

from notary_core.canon import canonical_json
from notary_core.models import Lane, NotaryModel
from notary_world.cassette import cassette_key
from notary_world.models import Cassette, CassetteEntry, CassetteTurn

DEFAULT_MODEL: str = "openai/gpt-oss-120b"
"""The Groq model every prompt names and every live call uses. It is part of the prompt, so it is
part of the cassette key: changing it means re-recording the cassettes."""
DEFAULT_MAX_TOKENS: int = 1024


class LlmToolSpec(NotaryModel):
    name: str
    description: str
    input_schema: str
    """Canonical JSON text of the tool's parameter schema."""


class LlmRequest(NotaryModel):
    model: str
    system: str
    messages: tuple[CassetteTurn, ...]
    tools: tuple[LlmToolSpec, ...]
    max_tokens: int


class LlmClient(Protocol):
    def complete(self, request: LlmRequest) -> CassetteTurn: ...


class CassetteMissError(KeyError):
    """Replay found no entry for this lane and prompt."""


class CassetteConflictError(ValueError):
    """One key was recorded with two different responses."""


class ScriptExhaustedError(RuntimeError):
    """A `ScriptedClient` was asked for more answers than it was given."""


def prompt_text(request: LlmRequest) -> str:
    """The exact prompt a cassette key is computed from: canonical JSON of the whole request."""
    return canonical_json(request.model_dump(mode="json"))


def cassette_json(cassette: Cassette) -> str:
    """What a recording script writes to `packages/world/fixtures/cassettes/<name>.json`."""
    return cassette.model_dump_json(indent=2) + "\n"


class CassetteClient:
    """Replays a cassette; a prompt it never recorded is an error, never a fallback."""

    def __init__(self, cassette: Cassette) -> None:
        self._lane: Lane = cassette.lane
        answers: dict[str, CassetteTurn] = {}
        for entry in cassette.entries:
            known = answers.get(entry.key)
            if known is not None and known != entry.response:
                raise CassetteConflictError(entry.key)
            answers[entry.key] = entry.response
        self._answers = answers

    def complete(self, request: LlmRequest) -> CassetteTurn:
        key = cassette_key(self._lane, prompt_text(request))
        answer = self._answers.get(key)
        if answer is None:
            raise CassetteMissError(key)
        return answer


class RecordingClient:
    """Forwards to another client and remembers every answer, in call order."""

    def __init__(self, inner: LlmClient, *, lane: Lane, name: str, model: str) -> None:
        self._inner = inner
        self._lane: Lane = lane
        self._name = name
        self._model = model
        self._entries: dict[str, CassetteEntry] = {}

    def complete(self, request: LlmRequest) -> CassetteTurn:
        response = self._inner.complete(request)
        key = cassette_key(self._lane, prompt_text(request))
        known = self._entries.get(key)
        if known is None:
            self._entries[key] = CassetteEntry(key=key, response=response)
        elif known.response != response:
            raise CassetteConflictError(key)
        return response

    def cassette(self) -> Cassette:
        return Cassette(
            name=self._name,
            model=self._model,
            lane=self._lane,
            entries=tuple(self._entries.values()),
        )


class ScriptedClient:
    """Test double: returns the given turns in order and records every request."""

    def __init__(self, turns: Sequence[CassetteTurn]) -> None:
        self._turns = tuple(turns)
        self._seen: list[LlmRequest] = []

    @property
    def requests(self) -> tuple[LlmRequest, ...]:
        return tuple(self._seen)

    def complete(self, request: LlmRequest) -> CassetteTurn:
        index = len(self._seen)
        self._seen.append(request)
        if index >= len(self._turns):
            raise ScriptExhaustedError(f"script has {len(self._turns)} turns")
        return self._turns[index]
