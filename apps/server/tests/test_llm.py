import pytest
from pydantic import ValidationError

from notary_core.models import Lane
from notary_server.llm import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL,
    CassetteClient,
    CassetteConflictError,
    CassetteMissError,
    LlmRequest,
    LlmToolSpec,
    RecordingClient,
    ScriptedClient,
    ScriptExhaustedError,
    cassette_json,
    prompt_text,
)
from notary_world.cassette import cassette_key
from notary_world.models import Cassette, CassetteEntry, CassetteToolCall, CassetteTurn

LANES: tuple[Lane, ...] = ("undefended", "classifier", "notary")


def turn(role: str, content: str, *calls: tuple[str, dict[str, str]]) -> CassetteTurn:
    return CassetteTurn.model_validate(
        {
            "role": role,
            "content": content,
            "tool_calls": tuple({"tool": tool, "args": args} for tool, args in calls),
        }
    )


def request(
    text: str = "Pay my December bill",
    *,
    system: str = "You are an assistant.",
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    schema: str = '{"type":"object"}',
) -> LlmRequest:
    return LlmRequest(
        model=model,
        system=system,
        messages=(turn("user", text),),
        tools=(LlmToolSpec(name="read_inbox", description="List mail.", input_schema=schema),),
        max_tokens=max_tokens,
    )


@pytest.mark.invariant("I6")
def test_prompt_text_is_deterministic_and_sensitive() -> None:
    base = request()
    assert prompt_text(base) == prompt_text(request())
    variants = [
        request(system="other"),
        request(text="Pay my November bill"),
        request(schema='{"type":"object","properties":{}}'),
        request(model="claude-opus-5-5"),
        request(max_tokens=DEFAULT_MAX_TOKENS + 1),
    ]
    texts = {prompt_text(v) for v in variants}
    assert prompt_text(base) not in texts
    assert len(texts) == len(variants)


@pytest.mark.invariant("I6")
def test_key_depends_on_the_lane() -> None:
    text = prompt_text(request())
    keys = {cassette_key(lane, text) for lane in LANES}
    assert len(keys) == 3


@pytest.mark.invariant("I6")
def test_cassette_client_hits_and_misses() -> None:
    answer = turn("assistant", "Reading.", ("read_inbox", {}))
    entry = CassetteEntry(key=cassette_key("notary", prompt_text(request())), response=answer)
    client = CassetteClient(Cassette(name="c", model="m", lane="notary", entries=(entry,)))
    assert client.complete(request()) == answer
    with pytest.raises(CassetteMissError):
        client.complete(request("something else"))


@pytest.mark.invariant("I6")
def test_cassette_client_is_lane_isolated() -> None:
    answer = turn("assistant", "ok")
    entry = CassetteEntry(key=cassette_key("classifier", prompt_text(request())), response=answer)
    cassette = Cassette(name="c", model="m", lane="notary", entries=(entry,))
    with pytest.raises(CassetteMissError):
        CassetteClient(cassette).complete(request())


@pytest.mark.invariant("I6")
def test_cassette_client_rejects_conflicting_entries() -> None:
    key = cassette_key("notary", prompt_text(request()))
    entries = (
        CassetteEntry(key=key, response=turn("assistant", "a")),
        CassetteEntry(key=key, response=turn("assistant", "b")),
    )
    with pytest.raises(CassetteConflictError):
        CassetteClient(Cassette(name="c", model="m", lane="notary", entries=entries))


@pytest.mark.invariant("I6")
def test_recording_then_replay_round_trips() -> None:
    requests = [request("one"), request("two"), request("three")]
    turns = [turn("assistant", f"answer {i}", ("read_inbox", {})) for i in range(3)]
    recorder = RecordingClient(ScriptedClient(turns), lane="notary", name="rec", model="m")
    assert [recorder.complete(r) for r in requests] == turns
    text = cassette_json(recorder.cassette())
    replay = CassetteClient(Cassette.model_validate_json(text))
    assert [replay.complete(r) for r in requests] == turns


@pytest.mark.invariant("I6")
def test_recording_dedupes_and_detects_conflicts() -> None:
    same = turn("assistant", "same")
    recorder = RecordingClient(
        ScriptedClient([same, same, turn("assistant", "different")]),
        lane="notary",
        name="rec",
        model="m",
    )
    recorder.complete(request())
    recorder.complete(request())
    assert len(recorder.cassette().entries) == 1
    with pytest.raises(CassetteConflictError):
        recorder.complete(request())


@pytest.mark.invariant("I6")
def test_cassette_metadata() -> None:
    recorder = RecordingClient(
        ScriptedClient([turn("assistant", "x")]), lane="classifier", name="n", model="mm"
    )
    recorder.complete(request())
    cassette = recorder.cassette()
    assert (cassette.name, cassette.model, cassette.lane) == ("n", "mm", "classifier")
    assert cassette.entries[0].key == cassette_key("classifier", prompt_text(request()))


@pytest.mark.invariant("I6")
def test_cassette_json_is_stable() -> None:
    cassette = Cassette(
        name="c",
        model="m",
        lane="notary",
        entries=(
            CassetteEntry(
                key=cassette_key("notary", "p"),
                response=CassetteTurn(
                    role="assistant",
                    content="x",
                    tool_calls=(CassetteToolCall(tool="t", args={"a": "b"}),),
                ),
            ),
        ),
    )
    assert cassette_json(cassette) == cassette_json(cassette)
    assert cassette_json(cassette).endswith("}\n")
    assert Cassette.model_validate_json(cassette_json(cassette)) == cassette


@pytest.mark.invariant("I6")
def test_scripted_client_order_and_exhaustion() -> None:
    turns = [turn("assistant", "a"), turn("assistant", "b")]
    client = ScriptedClient(turns)
    assert client.complete(request("1")) == turns[0]
    assert client.complete(request("2")) == turns[1]
    assert [r.messages[0].content for r in client.requests] == ["1", "2"]
    with pytest.raises(ScriptExhaustedError):
        client.complete(request("3"))


@pytest.mark.invariant("I6")
def test_requests_are_strict_models() -> None:
    with pytest.raises(ValidationError):
        LlmRequest.model_validate(
            {"model": "m", "system": "s", "messages": [], "tools": [], "max_tokens": "x"}
        )
