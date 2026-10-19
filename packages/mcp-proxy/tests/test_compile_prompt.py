"""The first prompt compiles the contract (#265, phase 2: `--compile-url`).

The proxy asks the NOTARY server to compile a contract from the user's first prompt and uses the
answer only if it is no wider than the config's (`widening_reasons`). `run_started` is deferred so
the contract is settled before it is written; once anything else has started the run, the config's
contract is frozen. No test reaches the network: the transport is injected, or a server on a free
loopback port is a thread of the test. Nothing sleeps on the wall clock.
"""

import json
import socket
import threading
from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from builders import RecordingBackend, make_contract, make_gateway
from stdio_session import StdioSession, proxy_command, request, tool_call
from test_dispatch import GatedBackend, Wire
from test_user_prompt import PATIENCE, PROMPT, empty_ledger_config, run_prompt_hook, text_of

from notary_core.contract import ContractWideningError, widening_reasons
from notary_core.models import (
    AuditEntry,
    Event,
    FreeMarker,
    IntentContract,
    RunFinished,
    RunStarted,
    ValueLabeled,
)
from notary_core.pinning import ToolManifest
from notary_mcp_proxy.client import StdioClient
from notary_mcp_proxy.compile_client import (
    COMPILE_TIMEOUT,
    MAX_RESPONSE,
    CompileClient,
    CompileClientError,
    CompileTarget,
    CompileUrlError,
    PromptCompiler,
    narrow,
    parse_compile_url,
    post_json,
)
from notary_mcp_proxy.config import ProxyConfig, build_contract
from notary_mcp_proxy.dispatch import PROMPT_WAIT
from notary_mcp_proxy.gateway import Gateway
from notary_mcp_proxy.jsonrpc import JsonObject, as_object
from notary_mcp_proxy.main import build_server, main
from notary_mcp_proxy.prompt_hook import HOOK_TIMEOUT
from notary_mcp_proxy.server import COMPILING_PROMPT_WAIT, ProxyServer

URL = "http://127.0.0.1:8000/mcp/compile"
COMPILED_ID = "contract-0123456789ab"


def answer(contract: IntentContract) -> bytes:
    return json.dumps({"contract": contract.model_dump(mode="json"), "dropped": []}).encode()


def narrower(base: IntentContract, *, keep: Sequence[str] = ("read_inbox", "pay_bill")) -> bytes:
    """What the compiler would send: the prompt's id and intent, fewer tools, a smaller budget."""
    contract = base.model_copy(
        update={
            "contract_id": COMPILED_ID,
            "user_intent": PROMPT,
            "allowed_tools": tuple(s for s in base.allowed_tools if s.tool in keep),
            "budget": base.budget.model_copy(update={"max_effects": 2}),
        }
    )
    return answer(contract)


def widened(base: IntentContract, update: dict[str, object]) -> bytes:
    contract = base.model_copy(update={"contract_id": COMPILED_ID, "user_intent": PROMPT, **update})
    return answer(contract)


class FakeServer:
    """The injected transport: records every body and answers with `reply` (or raises it)."""

    def __init__(self, reply: bytes | Exception) -> None:
        self.reply = reply
        self.posted: list[JsonObject] = []
        self.timeouts: list[float] = []
        self.entered: threading.Event | None = None
        self.release: threading.Event | None = None
        """When set, a post announces itself on `entered` and waits for `release`."""

    def __call__(self, target: CompileTarget, body: bytes, timeout: float) -> bytes:
        self.timeouts.append(timeout)
        if self.entered is not None and self.release is not None:
            self.entered.set()
            assert self.release.wait(PATIENCE)
        self.posted.append(json.loads(body))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


class Rig:
    def __init__(self, reply_for: Callable[[IntentContract], bytes | Exception]) -> None:
        self.backend = GatedBackend()
        self.base = make_contract(self.backend)
        self.fake = FakeServer(reply_for(self.base))
        self.gateway: Gateway = make_gateway(self.backend, contract=self.base)
        self.gateway.defer_start("mcp-proxy")
        compiler = PromptCompiler(
            CompileClient(URL, transport=self.fake), self.base, self.backend.list_tools()
        )
        self.server = ProxyServer(self.gateway, [], prompt_compiler=compiler)

    def started_with(self) -> IntentContract:
        first = self.gateway.chain[0].event
        assert isinstance(first, RunStarted)
        return first.contract

    def tool_call(self, name: str, arguments: JsonObject | None = None) -> JsonObject:
        reply = self.server.handle(tool_call(1, name, arguments or {}))
        assert reply is not None
        result = as_object(reply.get("result"))
        assert result is not None
        return result


# -- narrowing is accepted, widening is refused ----------------------------------------------------


def test_the_run_starts_with_the_compiled_contract_when_it_narrows() -> None:
    rig = Rig(narrower)
    assert rig.gateway.chain == ()  # deferred: nothing is written before the first prompt
    assert rig.server.add_user_prompt(PROMPT) == "request.1"
    contract = rig.started_with()
    assert [s.tool for s in contract.allowed_tools] == ["read_inbox", "pay_bill"]
    assert contract.budget.max_effects == 2
    assert widening_reasons(rig.base, contract) == ()  # I5, with the core's own function
    # The two labels are the config's (the core wants them equal); the rest is the compiler's.
    assert (contract.contract_id, contract.user_intent) == (
        rig.base.contract_id,
        rig.base.user_intent,
    )
    events = [e.event for e in rig.gateway.chain]
    assert isinstance(events[0], RunStarted)  # run_started is the first entry...
    assert isinstance(events[1], ValueLabeled)  # ...and the prompt follows it
    assert events[1].value.id == "request.1"
    assert rig.gateway.contract == contract
    # The tool dropped by the compiler is out of scope for the whole run.
    refused = rig.tool_call("add_contact", {"name": "Sam"})
    assert refused["isError"] is True
    assert "scope" in text_of_result(refused)
    assert rig.backend.calls == []


def text_of_result(result: JsonObject) -> str:
    content = result["content"]
    assert isinstance(content, list)
    return "\n".join(str(block["text"]) for block in content if isinstance(block, dict))


def test_only_the_contract_tools_and_the_prompt_are_posted() -> None:
    rig = Rig(narrower)
    rig.server.add_user_prompt(PROMPT)
    (posted,) = rig.fake.posted
    assert posted["request"] == PROMPT
    manifests = posted["manifests"]
    assert isinstance(manifests, list)
    names = {str(m["name"]) for m in manifests if isinstance(m, dict)}
    assert names == {scope.tool for scope in rig.base.allowed_tools}
    pinned = {m.name: m for m in rig.backend.list_tools()}
    for entry in manifests:
        assert isinstance(entry, dict)
        assert ToolManifest.model_validate(entry) == pinned[str(entry["name"])]
    assert rig.fake.timeouts == [COMPILE_TIMEOUT]


def test_narrow_accepts_the_same_contract_and_a_removed_tool() -> None:
    base = make_contract(RecordingBackend())
    same = base.model_copy(update={"contract_id": "other", "user_intent": "other"})
    assert narrow(base, same) == (base, ())
    smaller = same.model_copy(update={"allowed_tools": base.allowed_tools[:1]})
    accepted, reasons = narrow(base, smaller)
    assert reasons == ()
    assert accepted is not None
    assert [s.tool for s in accepted.allowed_tools] == [base.allowed_tools[0].tool]


def extra_tool(base: IntentContract) -> dict[str, object]:
    scope = base.allowed_tools[0].model_copy(update={"tool": "send_money"})
    return {"allowed_tools": (*base.allowed_tools, scope)}


def bigger_budget(base: IntentContract) -> dict[str, object]:
    budget = base.budget.model_copy(update={"max_spend_cents": base.budget.max_spend_cents + 1})
    return {"budget": budget}


def relaxed_marker(base: IntentContract) -> dict[str, object]:
    scopes = tuple(
        s.model_copy(update={"params": {**s.params, "payee": FreeMarker(kind="free")}})
        if s.tool == "pay_bill"
        else s
        for s in base.allowed_tools
    )
    return {"allowed_tools": scopes}


def other_manifest(base: IntentContract) -> dict[str, object]:
    scopes = tuple(
        s.model_copy(update={"manifest_hash": "0" * 64}) if s.tool == "pay_bill" else s
        for s in base.allowed_tools
    )
    return {"allowed_tools": scopes}


def new_host(base: IntentContract) -> dict[str, object]:
    return {"egress_hosts": ("evil.example",)}


def weaker_effect(base: IntentContract) -> dict[str, object]:
    scopes = tuple(
        s.model_copy(update={"effect": "read"}) if s.tool == "pay_bill" else s
        for s in base.allowed_tools
    )
    return {"allowed_tools": scopes, "authorized_irreversible": ()}


WIDENINGS: list[tuple[str, Callable[[IntentContract], dict[str, object]], str]] = [
    ("a tool added", extra_tool, "tool added: send_money"),
    ("a bigger budget", bigger_budget, "budget widened: max_spend_cents"),
    ("a marker relaxed", relaxed_marker, "marker relaxed: pay_bill.payee"),
    ("a different manifest", other_manifest, "manifest changed: pay_bill"),
    ("an egress host", new_host, "egress host added: evil.example"),
    ("a weaker effect class", weaker_effect, "effect widened: pay_bill"),
]


@pytest.mark.parametrize(
    ("change", "reason"),
    [(c, r) for _, c, r in WIDENINGS],
    ids=[label for label, _, _ in WIDENINGS],
)
def test_a_contract_that_widens_the_config_is_refused_and_the_config_kept(
    change: Callable[[IntentContract], dict[str, object]],
    reason: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rig = Rig(lambda base: widened(base, change(base)))
    assert rig.server.add_user_prompt(PROMPT) == "request.1"  # the prompt itself is still stored
    assert rig.started_with() == rig.base  # the config's contract, unchanged
    assert rig.gateway.contract == rig.base
    err = capsys.readouterr().err
    assert "kept the config contract" in err
    assert reason in err
    assert PROMPT not in err


def test_a_compiled_contract_that_adds_a_tool_is_refused_issue_example() -> None:
    """Phase 2 narrowing test of the issue: one that adds a tool is refused, one that removes is
    accepted."""
    added = Rig(lambda base: widened(base, extra_tool(base)))
    added.server.add_user_prompt(PROMPT)
    assert added.started_with() == added.base
    removed = Rig(narrower)
    removed.server.add_user_prompt(PROMPT)
    assert removed.started_with() != removed.base


# -- every failure keeps the config ----------------------------------------------------------------


def failures() -> list[tuple[str, Callable[[IntentContract], bytes | Exception]]]:
    return [
        ("server down", lambda _: CompileClientError("the compile server could not be reached")),
        ("timeout", lambda _: CompileClientError("the compile server did not answer in time")),
        ("bad status", lambda _: CompileClientError("the compile server answered status 500")),
        ("not json", lambda _: b"<html>oops</html>"),
        ("not an object", lambda _: b"[]"),
        ("no contract", lambda _: b'{"dropped": []}'),
        ("invalid contract", lambda _: b'{"contract": {"contract_id": 1}, "dropped": []}'),
        (
            "extra key",
            lambda base: json.dumps(
                {"contract": json.loads(answer(base))["contract"], "dropped": [], "x": 1}
            ).encode(),
        ),
        ("transport bug", lambda _: RuntimeError("secret detail that must not be printed")),
    ]


@pytest.mark.parametrize(("label", "reply"), failures(), ids=[label for label, _ in failures()])
def test_any_failure_keeps_the_config_contract(
    label: str,
    reply: Callable[[IntentContract], bytes | Exception],
    capsys: pytest.CaptureFixture[str],
) -> None:
    rig = Rig(reply)
    assert rig.server.add_user_prompt(PROMPT) == "request.1"
    assert rig.started_with() == rig.base
    err = capsys.readouterr().err
    assert "compile: kept the config contract" in err
    assert "secret detail" not in err
    assert PROMPT not in err
    # And the run goes on as it always did: the typed prompt is a trusted value.
    assert rig.tool_call("read_inbox")["isError"] is False


def test_a_hostile_reason_is_quoted_on_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    def hostile(base: IntentContract) -> bytes | Exception:
        scope = base.allowed_tools[0].model_copy(update={"tool": "x\x1b[2J\nforged line"})
        return widened(base, {"allowed_tools": (*base.allowed_tools, scope)})

    rig = Rig(hostile)
    rig.server.add_user_prompt(PROMPT)
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "\nforged line" not in err


# -- the window: the first prompt only -------------------------------------------------------------


def test_a_second_prompt_never_recompiles() -> None:
    rig = Rig(narrower)
    rig.server.add_user_prompt(PROMPT)
    first = rig.started_with()
    assert rig.server.add_user_prompt("and then pay Sam") == "request.2"
    assert len(rig.fake.posted) == 1
    assert rig.gateway.contract == first
    assert rig.gateway.contract is not rig.base


def test_a_first_prompt_that_failed_does_not_let_the_second_compile() -> None:
    rig = Rig(lambda _: CompileClientError("the compile server could not be reached"))
    rig.server.add_user_prompt(PROMPT)
    rig.fake.reply = narrower(rig.base)  # the server is back, too late
    rig.server.add_user_prompt("second")
    assert len(rig.fake.posted) == 1
    assert rig.gateway.contract == rig.base


def test_a_tool_call_before_any_prompt_starts_the_run_with_the_config_contract() -> None:
    rig = Rig(narrower)
    assert rig.tool_call("read_inbox")["isError"] is False
    assert rig.started_with() == rig.base
    assert rig.server.add_user_prompt(PROMPT) == "request.1"  # still stored, still trusted
    assert rig.fake.posted == []  # but never compiled
    assert rig.gateway.contract == rig.base
    starts = [e for e in rig.gateway.chain if isinstance(e.event, RunStarted)]
    assert len(starts) == 1


def test_a_call_that_wrote_nothing_still_closes_the_window() -> None:
    """A call to a tool outside the contract is blocked at once; it must not leave the window
    open for a later prompt to replace the contract."""
    rig = Rig(narrower)
    rig.tool_call("not_a_tool")
    assert isinstance(rig.gateway.chain[0].event, RunStarted)
    rig.server.add_user_prompt(PROMPT)
    assert rig.fake.posted == []
    assert rig.gateway.contract == rig.base


@pytest.mark.parametrize("starter", ["drift", "finish", "call"])
def test_anything_that_needs_the_chain_closes_the_window(starter: str) -> None:
    rig = Rig(narrower)
    if starter == "drift":
        rig.server.check_drift_now()
    elif starter == "finish":
        rig.server.finish_run()
    else:
        rig.tool_call("read_inbox")
    first = rig.gateway.chain[0].event
    assert isinstance(first, RunStarted)
    assert first.contract == rig.base
    rig.server.add_user_prompt(PROMPT)
    assert rig.fake.posted == []
    assert rig.gateway.contract == rig.base


def test_a_run_with_no_prompt_and_no_call_still_has_run_started_first() -> None:
    rig = Rig(narrower)
    rig.server.finish_run()
    kinds = [type(e.event) for e in rig.gateway.chain]
    assert kinds == [RunStarted, RunFinished]
    assert rig.gateway.chain[0].index == 0


def test_fast_methods_do_not_close_the_window() -> None:
    rig = Rig(narrower)
    for method in ("initialize", "ping", "tools/list"):
        assert rig.server.handle({"jsonrpc": "2.0", "id": 1, "method": method}) is not None
    assert rig.gateway.chain == ()
    rig.server.add_user_prompt(PROMPT)
    assert len(rig.fake.posted) == 1


# -- the Gateway: adopt_contract and the deferred start --------------------------------------------


def test_adopt_contract_works_before_the_run_starts_and_refuses_after() -> None:
    backend = RecordingBackend()
    base = make_contract(backend)
    gateway = make_gateway(backend, contract=base)
    gateway.defer_start("mcp-proxy")
    smaller = base.model_copy(
        update={"allowed_tools": base.allowed_tools[:1], "authorized_irreversible": ()}
    )
    gateway.adopt_contract(smaller)
    assert gateway.contract == smaller
    assert gateway.chain == ()
    assert gateway.ensure_started() is True
    assert gateway.ensure_started() is True  # once only
    (entry,) = gateway.chain
    assert isinstance(entry.event, RunStarted)
    assert entry.event.contract == smaller
    with pytest.raises(ValueError, match="frozen"):
        gateway.adopt_contract(smaller)
    assert gateway.contract == smaller


def test_adopt_contract_refuses_a_widening_even_before_the_start() -> None:
    backend = RecordingBackend()
    base = make_contract(backend)
    gateway = make_gateway(backend, contract=base)
    gateway.defer_start("mcp-proxy")
    wider = base.model_copy(update={"budget": base.budget.model_copy(update={"max_effects": 99})})
    with pytest.raises(ContractWideningError):
        gateway.adopt_contract(wider)
    assert gateway.contract == base


def test_adopt_contract_refuses_once_any_event_is_in_the_chain() -> None:
    backend = RecordingBackend()
    base = make_contract(backend)
    gateway = make_gateway(backend, contract=base)  # not deferred: the caller emits run_started
    assert gateway.add_user_value("hello") is not None
    with pytest.raises(ValueError, match="frozen"):
        gateway.adopt_contract(base)


def test_any_emit_starts_a_deferred_run_first() -> None:
    backend = RecordingBackend()
    gateway = make_gateway(backend)
    gateway.defer_start("mcp-proxy")
    gateway.add_user_value("hello")
    kinds = [type(e.event) for e in gateway.chain]
    assert kinds == [RunStarted, ValueLabeled]


def test_a_failed_run_started_append_halts_and_nothing_else_is_written() -> None:
    attempts: list[str] = []

    def failing(chain: Sequence[AuditEntry], event: Event) -> tuple[AuditEntry, ...]:
        attempts.append(event.type)
        raise OSError("disk full")

    gateway = make_gateway(RecordingBackend(), audit_append=failing)
    gateway.defer_start("mcp-proxy")
    assert gateway.add_user_value("hello") is None
    assert gateway.halted is not None
    assert gateway.add_user_value("again") is None
    assert attempts == ["run_started"]  # no event was ever tried before run_started


def test_defer_start_needs_an_empty_chain() -> None:
    gateway = make_gateway(RecordingBackend())
    gateway.add_user_value("hello")
    with pytest.raises(ValueError, match="started"):
        gateway.defer_start("mcp-proxy")


def test_without_a_compile_client_run_started_is_written_at_startup(tmp_path: Path) -> None:
    config = ProxyConfig.model_validate_json(empty_ledger_config(tmp_path).read_bytes())
    client = StdioClient(config.server.command)
    try:
        server = build_server(config, client, run_id="run-test")
        (entry,) = server.gateway.chain  # unchanged: run_started is entry 0, right away
        assert isinstance(entry.event, RunStarted)
        assert entry.event.contract.contract_id == "mcp-proxy"
    finally:
        client.close()


def test_with_a_compile_client_nothing_is_written_at_startup(tmp_path: Path) -> None:
    config = ProxyConfig.model_validate_json(empty_ledger_config(tmp_path).read_bytes())
    client = StdioClient(config.server.command)
    try:
        server = build_server(
            config,
            client,
            run_id="run-test",
            compile_client=CompileClient(URL, transport=FakeServer(b"")),
        )
        assert server.gateway.chain == ()
        assert server.add_user_prompt(PROMPT) == "request.1"
        assert isinstance(server.gateway.chain[0].event, RunStarted)
    finally:
        client.close()


# -- timing ----------------------------------------------------------------------------------------


def test_the_waits_fit_inside_each_other_and_inside_claude_codes_30_seconds() -> None:
    assert COMPILE_TIMEOUT == 15.0
    assert PROMPT_WAIT == 3.0
    assert COMPILING_PROMPT_WAIT == COMPILE_TIMEOUT + PROMPT_WAIT  # the compile, then the appends
    worst = PROMPT_WAIT + COMPILING_PROMPT_WAIT  # queued wait, then the wait on a running prompt
    assert worst == 21.0
    assert worst < HOOK_TIMEOUT < 30.0  # the hook never gives up on a prompt the proxy stores


def test_a_first_prompt_the_worker_is_still_compiling_is_waited_for_the_compile_time() -> None:
    """The control thread waits `PROMPT_WAIT` for the worker to take the prompt; when the worker
    has (it is compiling), it waits up to `COMPILING_PROMPT_WAIT` for the end of it. The injected
    `Wait` stands for the clock: its first call returns False once the compile has begun (as if 3 s
    had passed), its second one is given the longer timeout and waits for the real answer."""
    rig = Rig(narrower)
    entered = threading.Event()
    release = threading.Event()
    rig.fake.entered = entered
    rig.fake.release = release
    asked: list[float] = []

    def wait(event: threading.Event, timeout: float) -> bool:
        asked.append(timeout)
        if len(asked) == 1:
            assert entered.wait(PATIENCE)  # the worker is inside the compile
            release.set()
            return False  # "PROMPT_WAIT elapsed"
        return event.wait(PATIENCE)

    wire = Wire(rig.backend, wait=wait, server=rig.server)
    try:
        assert rig.server.submit_user_prompt(PROMPT) == "request.1"
    finally:
        wire.close_input()
        wire.thread.join(PATIENCE)
    assert asked == [PROMPT_WAIT, COMPILING_PROMPT_WAIT]
    assert rig.gateway.contract != rig.base  # the compile finished and was adopted
    assert isinstance(rig.gateway.chain[0].event, RunStarted)


def test_the_longer_wait_is_only_for_the_first_prompt() -> None:
    rig = Rig(narrower)
    seen: list[tuple[float, float | None]] = []

    def submit(
        text: str, *, timeout: float = PROMPT_WAIT, run_timeout: float | None = None
    ) -> str | None:
        seen.append((timeout, run_timeout))
        return "request.1"

    rig.server.route_user_prompts(submit)
    rig.server.submit_user_prompt(PROMPT)
    assert seen == [(PROMPT_WAIT, COMPILING_PROMPT_WAIT)]
    rig.server.add_user_prompt(PROMPT)  # the window closes with the first prompt
    seen.clear()
    rig.server.submit_user_prompt("again")
    assert seen == [(PROMPT_WAIT, None)]


def test_a_proxy_without_compile_waits_as_before() -> None:
    seen: list[tuple[float, float | None]] = []

    def submit(
        text: str, *, timeout: float = PROMPT_WAIT, run_timeout: float | None = None
    ) -> str | None:
        seen.append((timeout, run_timeout))
        return "request.1"

    server = ProxyServer(make_gateway(RecordingBackend()), [])
    server.route_user_prompts(submit)
    server.submit_user_prompt(PROMPT)
    assert seen == [(PROMPT_WAIT, None)]


# -- --compile-url ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/mcp/compile",
        "http://localhost:8000/mcp/compile",
        "http://127.0.0.1:1/",
    ],
)
def test_loopback_urls_are_accepted(url: str) -> None:
    target = parse_compile_url(url)
    assert target.host in ("127.0.0.1", "localhost")
    assert target.path.startswith("/")


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8000/mcp/compile",
        "http://example.com:8000/mcp/compile",
        "http://10.0.0.5:8000/mcp/compile",
        "http://0.0.0.0:8000/mcp/compile",
        "http://[::1]:8000/mcp/compile",
        "http://127.0.0.1/mcp/compile",
        "http://127.0.0.1:99999/mcp/compile",
        "http://user:pw@127.0.0.1:8000/mcp/compile",
        "http://127.0.0.1:8000@evil.example/mcp/compile",
        "http://127.0.0.1.evil.example:8000/mcp/compile",
        "http://localhost.evil.example:8000/mcp/compile",
        "http://127.0.0.1:8000/mcp/compile?x=1",
        "http://127.0.0.1:8000/mcp/compile#x",
        "http://127.0.0.1:8000/mcp compile",
        "http://127.0.0.1:8000/\r\nX: y",
        "ftp://127.0.0.1:8000/x",
        "127.0.0.1:8000/mcp/compile",
        "",
        "file:///etc/passwd",
    ],
)
def test_anything_but_a_loopback_http_url_with_a_port_is_refused(url: str) -> None:
    with pytest.raises(CompileUrlError):
        parse_compile_url(url)
    with pytest.raises(CompileUrlError):
        CompileClient(url)


def test_a_non_loopback_compile_url_fails_at_startup(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = empty_ledger_config(tmp_path)
    with pytest.raises(SystemExit) as stop:
        main(["--config", str(config), "--compile-url", "http://example.com:8000/mcp/compile"])
    assert stop.value.code == 2
    err = capsys.readouterr().err
    assert "loopback" in err or "127.0.0.1" in err
    assert not (tmp_path / "runs").exists()


def test_compile_url_needs_the_control_socket(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = empty_ledger_config(tmp_path)
    with pytest.raises(SystemExit) as stop:
        main(["--config", str(config), "--compile-url", URL, "--control", "none"])
    assert stop.value.code == 2
    assert "control socket" in capsys.readouterr().err


# -- the real transport, against a server on a free loopback port ----------------------------------


class Seen:
    def __init__(self) -> None:
        self.headers: list[dict[str, str]] = []
        self.bodies: list[bytes] = []
        self.paths: list[str] = []


@contextmanager
def local_server(
    status: int, body: Callable[[], bytes], seen: Seen
) -> Generator[tuple[str, ThreadingHTTPServer]]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            seen.bodies.append(self.rfile.read(length))
            seen.headers.append({k.lower(): v for k, v in self.headers.items()})
            seen.paths.append(self.path)
            payload = body()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/mcp/compile", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(PATIENCE)


def test_the_real_transport_posts_json_and_sends_no_origin_or_forwarding_header() -> None:
    backend = RecordingBackend()
    base = make_contract(backend)
    seen = Seen()
    with local_server(200, lambda: narrower(base), seen) as (url, _):
        compiler = PromptCompiler(CompileClient(url), base, backend.list_tools())
        accepted = compiler.compile(PROMPT)
    assert accepted is not None
    assert [s.tool for s in accepted.allowed_tools] == ["read_inbox", "pay_bill"]
    (headers,) = seen.headers
    assert seen.paths == ["/mcp/compile"]
    assert headers["content-type"] == "application/json"
    assert not {"origin", "forwarded", "x-forwarded-for", "x-forwarded-host", "x-real-ip"} & set(
        headers
    )
    assert json.loads(seen.bodies[0])["request"] == PROMPT


@pytest.mark.parametrize(
    ("status", "payload", "problem"),
    [
        (500, b'{"detail": "boom"}', "status 500"),
        (200, b" " * (MAX_RESPONSE + 1), "too large"),
        (200, b"not json", "not a valid contract"),
    ],
)
def test_the_real_transport_refuses_a_bad_status_an_oversize_and_a_bad_answer(
    status: int, payload: bytes, problem: str
) -> None:
    with (
        local_server(status, lambda: payload, Seen()) as (url, _),
        pytest.raises(CompileClientError, match=problem),
    ):
        CompileClient(url).compile(PROMPT, [])


def test_the_real_transport_with_nobody_listening_is_a_clean_error() -> None:
    with local_server(200, lambda: b"{}", Seen()) as (url, _):
        pass  # the server is shut down and its socket closed: the port is free again
    with pytest.raises(CompileClientError, match="could not be reached"):
        CompileClient(url).compile(PROMPT, [])


def test_the_real_transport_gives_up_on_a_server_that_never_answers() -> None:
    """A listening socket that never accepts or answers: the request ends at the deadline."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        target = CompileTarget(host="127.0.0.1", port=listener.getsockname()[1], path="/x")
        with pytest.raises(CompileClientError, match="in time"):
            post_json(target, b"{}", 0.05)  # the only real wait in this file: 50 ms
    finally:
        listener.close()


# -- the whole path: a real proxy, the real hook, a server on a loopback port ----------------------


def contract_for(config: ProxyConfig, body: JsonObject) -> bytes:
    raw = body["manifests"]
    assert isinstance(raw, list)
    manifests = [ToolManifest.model_validate(m) for m in raw]
    base = build_contract(config, manifests)
    keep = ("read_inbox", "pay_bill")
    contract = base.model_copy(
        update={
            "contract_id": COMPILED_ID,
            "user_intent": str(body["request"]),
            "allowed_tools": tuple(s for s in base.allowed_tools if s.tool in keep),
            "budget": base.budget.model_copy(update={"max_spend_cents": 15000}),
        }
    )
    return answer(contract)


def run_events(chain: Path):  # the parsed events, indexed the way the other tests do
    return [json.loads(line)["event"] for line in chain.read_text().splitlines()]


def test_the_demo_with_a_compiled_contract(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Prompt -> hook -> proxy -> compile server -> narrower contract in `run_started`, written
    after the prompt arrived and BEFORE the prompt's own `value_labeled`."""
    directory = tmp_path_factory.mktemp("compiled")
    config_path = empty_ledger_config(directory)
    config = ProxyConfig.model_validate_json(config_path.read_bytes())
    audit = directory / "runs"
    socket_path = directory / "c" / "bank.sock"
    seen = Seen()
    with local_server(200, lambda: contract_for(config, json.loads(seen.bodies[-1])), seen) as (
        url,
        _,
    ):
        session = StdioSession(
            proxy_command(
                config_path,
                "--audit-dir",
                str(audit),
                "--control",
                str(socket_path),
                "--compile-url",
                url,
            )
        )
        session.send(request(1, "initialize", {"protocolVersion": "2025-06-18"}))
        session.result(1)
        (chain,) = audit.glob("*.chain.jsonl")
        (anchor,) = audit.glob("*.anchor.json")
        assert chain.read_text() == ""  # deferred: the run has no event yet
        assert json.loads(anchor.read_text())["length"] == 0
        assert seen.bodies == []  # and nothing was asked yet
        hook = run_prompt_hook(socket_path, PROMPT)
        assert (hook.returncode, hook.stdout) == (0, "")
        assert "request.1" in hook.stderr
        session.send(tool_call(2, "read_inbox", {}))
        session.send(tool_call(3, "add_contact", {"name": "Sam"}))
        session.send(tool_call(4, "pay_bill", {"payee": "DE00ACME00000000000001", "amount": 120}))
        assert session.result(2)["isError"] is False
        assert session.result(3)["isError"] is True  # add_contact was compiled away
        assert "scope" in text_of(session, 3)
        assert session.result(4)["isError"] is False
        session.finish()
    assert len(seen.bodies) == 1  # one compile for the run
    assert "origin" not in seen.headers[0]
    events = run_events(chain)
    assert [e["type"] for e in events[:2]] == ["run_started", "value_labeled"]
    started = events[0]["contract"]
    assert sorted(s["tool"] for s in started["allowed_tools"]) == ["pay_bill", "read_inbox"]
    assert started["budget"]["max_spend_cents"] == 15000
    assert started["contract_id"] == "mcp-proxy"
    assert events[1]["value"]["id"] == "request.1"
    assert events[-1]["type"] == "run_finished"
    assert [e["type"] for e in events].count("run_started") == 1
    final = json.loads(anchor.read_text())
    assert final["length"] == len(events)


def test_an_unreachable_compile_server_keeps_the_config_end_to_end(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    directory = tmp_path_factory.mktemp("nocompile")
    config_path = empty_ledger_config(directory)
    audit = directory / "runs"
    socket_path = directory / "c" / "bank.sock"
    session = StdioSession(
        proxy_command(
            config_path,
            "--audit-dir",
            str(audit),
            "--control",
            str(socket_path),
            "--compile-url",
            "http://127.0.0.1:9/mcp/compile",  # the discard port: nothing listens
        )
    )
    session.send(request(1, "initialize", {"protocolVersion": "2025-06-18"}))
    session.result(1)
    hook = run_prompt_hook(socket_path, PROMPT)
    assert (hook.returncode, hook.stdout) == (0, "")
    assert "request.1" in hook.stderr
    session.send(tool_call(2, "read_inbox", {}))
    assert session.result(2)["isError"] is False
    session.finish()
    (chain,) = audit.glob("*.chain.jsonl")
    events = run_events(chain)
    assert events[0]["type"] == "run_started"
    assert sorted(s["tool"] for s in events[0]["contract"]["allowed_tools"]) == [
        "add_contact",
        "pay_bill",
        "read_inbox",
    ]


def test_a_tool_call_before_the_prompt_end_to_end(tmp_path_factory: pytest.TempPathFactory) -> None:
    directory = tmp_path_factory.mktemp("early")
    config_path = empty_ledger_config(directory)
    audit = directory / "runs"
    socket_path = directory / "c" / "bank.sock"
    seen = Seen()
    with local_server(200, lambda: b"{}", seen) as (url, _):
        session = StdioSession(
            proxy_command(
                config_path,
                "--audit-dir",
                str(audit),
                "--control",
                str(socket_path),
                "--compile-url",
                url,
            )
        )
        session.send(request(1, "initialize", {"protocolVersion": "2025-06-18"}))
        session.result(1)
        session.send(tool_call(2, "read_inbox", {}))
        assert session.result(2)["isError"] is False
        hook = run_prompt_hook(socket_path, PROMPT)
        assert "request.1" in hook.stderr
        session.finish()
    assert seen.bodies == []  # the call started the run: no compile after it
    (chain,) = audit.glob("*.chain.jsonl")
    events = run_events(chain)
    assert [e["type"] for e in events][:1] == ["run_started"]
    assert len([e for e in events if e["type"] == "run_started"]) == 1
