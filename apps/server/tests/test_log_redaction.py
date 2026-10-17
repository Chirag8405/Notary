"""The read token never reaches a log (#235).

The filter is unit-tested on its own; then one capture covers every logger it is attached to
(`uvicorn.access`, `uvicorn.error` and the `websockets` tree, including a child created after the
filter was attached); a control proves the capture would catch the token without the filter; and a
real uvicorn run on an ephemeral port shows what the servers actually print.
"""

import copy
import io
import json
import logging
import sys
import threading
import time
import urllib.request
from collections.abc import Generator, Iterator
from contextlib import contextmanager

import pytest
import uvicorn
import uvicorn.config
from fastapi import FastAPI
from tokens import OTHER_TOKEN, TOKEN
from uvicorn.logging import AccessFormatter
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

from notary_core.models import Event
from notary_server import log_redaction
from notary_server.app import create_app
from notary_server.log_redaction import (
    FILTER,
    REDACTED_TREES,
    RedactTokenFilter,
    attach_redaction,
    redact,
)
from notary_server.sources import RunMode, RunRequest, RunSource
from notary_world.golden import golden_streams

URL_WITH_TOKEN = f"/ws/runs/poisoned_bill?lane=notary&mode=cassette&token={TOKEN}"
COVERED = (
    "uvicorn.access",
    "uvicorn.error",
    "websockets",
    "websockets.server",
    "websockets.protocol",
)


# ------------------------------------------------------------------------------- the filter


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"GET /ws/runs/x?token={TOKEN} HTTP/1.1", "GET /ws/runs/x?token=[redacted] HTTP/1.1"),
        (
            f"/ws/runs/x?mode=cassette&token={TOKEN}&lane=notary",
            "/ws/runs/x?mode=cassette&token=[redacted]&lane=notary",
        ),
        (
            f'"WebSocket /ws/runs/x?token={TOKEN}" [accepted]',
            '"WebSocket /ws/runs/x?token=[redacted]" [accepted]',
        ),
        ("/ws/runs/x?token=", "/ws/runs/x?token=[redacted]"),
        (f"/ws/runs/x?TOKEN={TOKEN}", "/ws/runs/x?TOKEN=[redacted]"),
        ("/ws/runs/x?token=[redacted]", "/ws/runs/x?token=[redacted]"),
        ("/ws/runs/x?mode=cassette&lane=notary", "/ws/runs/x?mode=cassette&lane=notary"),
        ("no query here", "no query here"),
        (
            "POST /playground/hijacked/Ab3_-xYz9/calls HTTP/1.1",
            "POST /playground/hijacked/[redacted]/calls HTTP/1.1",
        ),
        ("GET /playground/hijacked/h1", "GET /playground/hijacked/[redacted]"),
        ("POST /playground/hijacked HTTP/1.1", "POST /playground/hijacked HTTP/1.1"),
        ("GET /playground/hijacked/ HTTP/1.1", "GET /playground/hijacked/ HTTP/1.1"),
        ("GET /playground/hijacked/[redacted]/calls", "GET /playground/hijacked/[redacted]/calls"),
        ("GET /playground/attacks/A3/run", "GET /playground/attacks/A3/run"),
    ],
)
def test_redact(text: str, expected: str) -> None:
    assert redact(text) == expected


def record(
    msg: object,
    args: tuple[object, ...] | dict[str, object] | None = None,
    exc_info: bool = False,
    stack_info: str | None = None,
) -> logging.LogRecord:
    made = logging.LogRecord(
        "websockets.server",
        logging.INFO,
        __file__,
        1,
        msg,
        args if not isinstance(args, dict) else (args,),
        sys.exc_info() if exc_info else None,
    )
    made.stack_info = stack_info
    return made


def test_the_filter_redacts_the_message_and_never_drops_a_record() -> None:
    made = record(f"GET /ws/runs/x?token={TOKEN}")
    assert FILTER.filter(made) is True
    assert made.getMessage() == "GET /ws/runs/x?token=[redacted]"


def test_the_filter_redacts_tuple_arguments() -> None:
    made = record("%s %s %d", ("127.0.0.1", f"/ws/x?token={TOKEN}", 200))
    FILTER.filter(made)
    assert made.getMessage() == "127.0.0.1 /ws/x?token=[redacted] 200"


def test_the_filter_keeps_a_placeholder_whose_argument_holds_the_token() -> None:
    """`"...?token=%s"` with the token as argument must not lose its placeholder, or logging
    would fail with "not all arguments converted" and drop the record."""
    made = record("GET /ws/x?token=%s HTTP/1.1", (TOKEN,))
    FILTER.filter(made)
    assert made.getMessage() == "GET /ws/x?token=[redacted] HTTP/1.1"
    named = record("%(path)s?token=%(token)s", {"path": "/ws/x", "token": TOKEN})
    FILTER.filter(named)
    assert named.getMessage() == "/ws/x?token=[redacted]"


def test_the_filter_redacts_a_mapping_argument() -> None:
    made = record("%(path)s", {"path": f"/ws/x?token={TOKEN}"})
    FILTER.filter(made)
    assert made.getMessage() == "/ws/x?token=[redacted]"


def test_the_filter_redacts_an_argument_that_is_not_a_string() -> None:
    class Request:
        def __str__(self) -> str:
            return f"Request(path=/ws/x?token={TOKEN})"

    made = record("%s", (Request(),))  # `%s` prints the str() of the object
    FILTER.filter(made)
    assert TOKEN not in made.getMessage()
    assert "token=[redacted]" in made.getMessage()
    printed_by_repr = record("%r", (Request(),))  # `%r` prints its repr, which holds no token
    FILTER.filter(printed_by_repr)
    assert TOKEN not in printed_by_repr.getMessage()  # (redacting it anyway is the safe side)


def test_the_filter_redacts_an_argument_whose_repr_holds_the_token() -> None:
    class Request:
        def __repr__(self) -> str:
            return f"Request(path=/ws/x?token={TOKEN})"

    made = record("%r", (Request(),))
    FILTER.filter(made)
    assert TOKEN not in made.getMessage()


def test_the_filter_redacts_a_message_object_that_is_not_a_string() -> None:
    class Message:
        def __str__(self) -> str:
            return f"/ws/x?token={TOKEN}"

    made = record(Message())
    FILTER.filter(made)
    assert made.getMessage() == "/ws/x?token=[redacted]"


def test_the_filter_redacts_the_exception_text_before_the_formatter_renders_it() -> None:
    try:
        raise ValueError(f"handshake failed for /ws/x?token={TOKEN}")
    except ValueError:
        made = record("failed", exc_info=True)
    assert made.exc_text is None  # the formatter would render the traceback later
    FILTER.filter(made)
    assert made.exc_text is not None
    assert TOKEN not in made.exc_text
    assert "token=[redacted]" in made.exc_text
    assert TOKEN not in logging.Formatter("%(message)s").format(made)


def test_the_filter_redacts_the_stack_text() -> None:
    made = record("x", stack_info=f"File q.py, in connect('/ws/x?token={TOKEN}')")
    FILTER.filter(made)
    assert made.stack_info is not None
    assert TOKEN not in made.stack_info


def test_the_filter_leaves_other_records_alone() -> None:
    made = record("%s took %d ms", ("poisoned_bill", 12))
    FILTER.filter(made)
    assert made.getMessage() == "poisoned_bill took 12 ms"
    assert made.exc_text is None


def test_the_filter_keeps_the_shape_uvicorns_access_formatter_unpacks() -> None:
    """uvicorn's `AccessFormatter` unpacks `record.args` as (client, method, path, http, status).
    A filter that flattened the record into a message with no arguments made it raise, and the
    line was lost (found by the e2e run, which uses uvicorn's own logging config)."""
    session_id = "Zk3_-Qw9sT2uYxLpAbCdEf"
    path = f"/playground/hijacked/{session_id}/calls"
    made = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:5000", "POST", path, "1.1", 200), None,
    )  # fmt: skip
    FILTER.filter(made)
    assert isinstance(made.args, tuple)
    assert len(made.args) == 5
    assert made.args[0] == "127.0.0.1:5000"
    assert made.args[4] == 200
    line = AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False)
    text = line.format(made)
    assert text == '127.0.0.1:5000 - "POST /playground/hijacked/[redacted]/calls HTTP/1.1" 200 OK'
    assert session_id not in text


def test_a_secret_built_from_the_template_and_an_argument_is_still_redacted() -> None:
    made = record("GET /playground/hijacked/%s/calls", ("abc123",))
    FILTER.filter(made)
    # Neither part is a secret alone; joined they are, so the rendered message is redacted.
    assert made.getMessage() == "GET /playground/hijacked/[redacted]/calls"


# ----------------------------------------------------------------------------- attaching


@pytest.fixture
def detached() -> Iterator[None]:
    """Start from the state before any app was made, so a test shows what `create_app` does and
    does not lean on an earlier test. The filter is attached again afterwards."""
    for logger in tree_loggers():
        logger.removeFilter(FILTER)
    factory = logging.getLogRecordFactory()
    if isinstance(factory, log_redaction.RedactingFactory):
        logging.setLogRecordFactory(factory.inner)
    yield
    attach_redaction()


def own_filters(name: str) -> list[object]:
    return [f for f in logging.getLogger(name).filters if f is FILTER]


def test_attach_redaction_is_idempotent() -> None:
    attach_redaction()
    attach_redaction()
    attach_redaction()
    for name in REDACTED_TREES:
        assert len(own_filters(name)) == 1, name
    factory = logging.getLogRecordFactory()
    assert isinstance(factory, log_redaction.RedactingFactory)
    assert not isinstance(factory.inner, log_redaction.RedactingFactory)


def test_every_app_attaches_the_filter(detached: None) -> None:
    assert all(own_filters(name) == [] for name in REDACTED_TREES)
    create_app(event_delay=0)
    create_app(event_delay=0)
    for name in REDACTED_TREES:
        assert len(own_filters(name)) == 1, name
    assert isinstance(logging.getLogRecordFactory(), log_redaction.RedactingFactory)


def test_a_filter_class_instance_is_the_one_attached() -> None:
    assert isinstance(FILTER, RedactTokenFilter)


# ------------------------------------------------------------- the record-factory fallback


def test_a_record_without_a_token_is_left_exactly_as_it_was() -> None:
    args = ("127.0.0.1", 200)
    try:
        raise ValueError("no secret here")
    except ValueError:
        made = record("%s answered %d", args, exc_info=True)
    exc_info = made.exc_info
    FILTER.filter(made)
    assert made.msg == "%s answered %d"
    assert made.args is args  # the same object, not a copy
    assert made.exc_info is exc_info
    assert made.exc_text is None  # the traceback is not rendered ahead of the formatter
    assert made.stack_info is None


class Spy:
    """A record factory that is already installed when the app is made: it must be chained to."""

    def __init__(self) -> None:
        self.inner = logging.getLogRecordFactory()
        self.made: list[str] = []

    def __call__(self, *args: object, **kwargs: object) -> logging.LogRecord:
        made = self.inner(*args, **kwargs)
        made.__dict__["spied"] = True
        self.made.append(made.name)
        return made


@contextmanager
def previous_factory(spy: Spy) -> Generator[None]:
    original = logging.getLogRecordFactory()
    logging.setLogRecordFactory(spy)
    try:
        yield
    finally:
        logging.setLogRecordFactory(original)


def test_the_factory_chains_to_the_previous_one(detached: None) -> None:
    spy = Spy()
    with previous_factory(spy):
        create_app(event_delay=0)
        factory = logging.getLogRecordFactory()
        assert isinstance(factory, log_redaction.RedactingFactory)
        assert factory.inner is spy
        made = logging.getLogger("websockets.server").makeRecord(
            "websockets.server", logging.INFO, __file__, 1, "x", (), None
        )
        assert getattr(made, "spied", False) is True  # the previous factory built the record
        assert spy.made == ["websockets.server"]


def test_the_factory_is_installed_once_however_many_apps_are_made(detached: None) -> None:
    spy = Spy()
    with previous_factory(spy):
        for _ in range(4):
            create_app(event_delay=0)
            attach_redaction()
        factory = logging.getLogRecordFactory()
        assert isinstance(factory, log_redaction.RedactingFactory)
        assert factory.inner is spy  # not wrapped in itself
        logging.getLogger("websockets.server").makeRecord(
            "websockets.server", logging.INFO, __file__, 1, "x", (), None
        )
        assert spy.made == ["websockets.server"]  # built once, not once per wrapper


def test_the_factory_redacts_only_the_trees_and_only_a_token(detached: None) -> None:
    create_app(event_delay=0)
    factory = logging.getLogRecordFactory()
    line = f"GET /ws/x?token={TOKEN}"
    inside = factory("websockets.server", logging.INFO, __file__, 1, line, (), None)
    child = factory("uvicorn.access", logging.INFO, __file__, 1, line, (), None)
    outside = factory("notary_server.app", logging.INFO, __file__, 1, line, (), None)
    clean_args = ("a", 1)
    clean = factory("websockets.server", logging.INFO, __file__, 1, "%s %d", clean_args, None)
    assert inside.getMessage() == "GET /ws/x?token=[redacted]"
    assert child.getMessage() == "GET /ws/x?token=[redacted]"
    assert outside.getMessage() == line  # not one of the covered loggers
    assert clean.args is clean_args
    assert clean.msg == "%s %d"


def test_a_logger_made_later_is_covered_by_the_factory_alone(detached: None) -> None:
    """No logger filter at all: the factory still redacts a child that did not exist yet."""
    create_app(event_delay=0)
    for logger in tree_loggers():
        logger.removeFilter(FILTER)
    late = logging.getLogger("websockets.a_child_nobody_attached_a_filter_to")
    assert FILTER not in late.filters
    with capturing((late.name,)) as capture:
        late.info("GET /ws/x?token=%s", TOKEN)
    assert TOKEN not in capture.text()
    assert "token=[redacted]" in capture.text()


# ------------------------------------------------------------------- one capture for all


class Capture(logging.Handler):
    """Keeps everything a record can print: message, exception text and the formatted line."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []
        self.names: set[str] = set()
        self.by_name: dict[str, list[str]] = {}
        self._formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")

    def emit(self, record: logging.LogRecord) -> None:
        self.names.add(record.name)
        self.by_name.setdefault(record.name, []).append(self._formatter.format(record))
        self.lines.append(self._formatter.format(record))
        self.lines.append(record.getMessage())
        if record.exc_text:
            self.lines.append(record.exc_text)

    def text(self) -> str:
        return "\n".join(self.lines)

    def text_of(self, name: str) -> str:
        """Everything the logger `name` (and no other) printed."""
        return "\n".join(self.by_name.get(name, []))


@contextmanager
def capturing(names: tuple[str, ...]) -> Generator[Capture]:
    """Capture the given loggers directly, so `propagate` settings do not matter."""
    capture = Capture()
    saved = {name: logging.getLogger(name).level for name in names}
    for name in names:
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.addHandler(capture)
    try:
        yield capture
    finally:
        for name in names:
            logger = logging.getLogger(name)
            logger.removeHandler(capture)
            logger.setLevel(saved[name])


def emit_request_lines(names: tuple[str, ...]) -> None:
    """What the servers print about a request: a request line, a handshake line, an error."""
    for name in names:
        logger = logging.getLogger(name)
        logger.info('%s - "WebSocket %s" [accepted]', "127.0.0.1:5000", URL_WITH_TOKEN)
        logger.debug("< GET %s HTTP/1.1", URL_WITH_TOKEN)
        logger.info(f"connection open for {URL_WITH_TOKEN}")
        try:
            raise RuntimeError(f"bad handshake {URL_WITH_TOKEN}")
        except RuntimeError:
            logger.exception("handshake failed")
        logger.warning("%(path)s", {"path": URL_WITH_TOKEN})


LATE_CHILD = "websockets.created_after_the_filter_was_attached"
BAD_TOKEN = "malformed-" + "q" * 9  # 19 characters: refused with 4400


def tree_loggers() -> list[logging.Logger]:
    names = {*COVERED, LATE_CHILD}
    names |= {
        name
        for name, logger in logging.Logger.manager.loggerDict.items()
        if isinstance(logger, logging.Logger) and log_redaction.in_redacted_tree(name)
    }
    return [logging.getLogger(name) for name in sorted(names)]


@contextmanager
def unredacted() -> Generator[None]:
    """The state before `attach_redaction()`: no filter on a logger, the plain record factory."""
    factory = logging.getLogRecordFactory()
    removed = [logger for logger in tree_loggers() if FILTER in logger.filters]
    for logger in removed:
        logger.removeFilter(FILTER)
    if isinstance(factory, log_redaction.RedactingFactory):
        logging.setLogRecordFactory(factory.inner)
    try:
        yield
    finally:
        logging.setLogRecordFactory(factory)
        for logger in removed:
            logger.addFilter(FILTER)


def test_the_token_is_in_no_record_of_any_covered_logger() -> None:
    attach_redaction()
    names = (*COVERED, LATE_CHILD)  # the child is made now, after the filter was attached
    with capturing(names) as capture:
        emit_request_lines(names)
    assert len(capture.lines) >= 5 * len(names)  # the capture saw the lines at all
    assert TOKEN not in capture.text()
    assert f"token={TOKEN}" not in capture.text()
    assert "token=[redacted]" in capture.text()


def test_control_the_capture_would_catch_the_token_without_the_filter() -> None:
    """Without the filter the same lines reach the capture with the token in them, so the test
    above cannot pass just because nothing was captured."""
    attach_redaction()
    names = (*COVERED, LATE_CHILD)
    with unredacted(), capturing(names) as capture:
        emit_request_lines(names)
    assert capture.text().count(TOKEN) >= len(names) * 4
    assert "[redacted]" not in capture.text()


# ----------------------------------------------------------------- a real uvicorn run


class TwoEvents:
    def check_available(self) -> None:
        return None

    def events(self, request: RunRequest) -> Iterator[Event]:
        return iter(golden_streams()["poisoned_bill.notary"][:2])


UVICORN_LOGGERS = ("uvicorn", "uvicorn.access", "uvicorn.error", "websockets")


def two_event_app() -> FastAPI:
    sources: dict[RunMode, RunSource] = {"cassette": TwoEvents()}
    return create_app(event_delay=0, sources=sources)  # attaches the filter


@contextmanager
def serving(app: FastAPI, log_config: dict[str, object] | None = None) -> Generator[int]:
    """The app on uvicorn (the pinned `websockets` implementation), on an ephemeral port, with
    uvicorn's own logging config off so every record reaches the capture."""
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        ws="websockets",
        log_config=log_config,
        log_level="debug",
        access_log=True,
        lifespan="off",
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield int(port)
    finally:
        server.should_exit = True
        thread.join(10)
        assert not thread.is_alive()


def get_list(port: int) -> None:
    """The REST list twice: with the header (the real client) and with a stray `?token=` in the
    query (a client that got it wrong), which uvicorn.access would print."""
    run = "run-poisoned_bill-notary"
    for query in ("", f"?token={TOKEN}"):
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/runs/{run}/endorsements{query}",
            headers={"X-Notary-Token": TOKEN},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200


def play_session(port: int) -> str:
    """Start a Hijacked Mode session, read it and make one call, over HTTP; returns its id."""
    base = f"http://127.0.0.1:{port}/playground/hijacked"

    def post(url: str, body: dict[str, object]) -> dict[str, object]:
        request = urllib.request.Request(
            url, data=json.dumps(body).encode(), headers={"content-type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    started = post(base, {"scenario": "legitimate_bill", "seed": 0})
    session_id = str(started["session_id"])
    with urllib.request.urlopen(f"{base}/{session_id}", timeout=5) as response:
        assert response.status == 200
    post(
        f"{base}/{session_id}/calls",
        {
            "type": "hijacked_tool_call",
            "run_id": started["run_id"],
            "call_id": "c1",
            "tool": "read_inbox",
            "args": {},
        },
    )
    return session_id


def talk(port: int) -> list[int]:
    """One good socket and one with a bad token (the close code of each), then the REST list."""
    codes: list[int] = []
    for query in (f"token={TOKEN}", f"token={BAD_TOKEN}", f"token={OTHER_TOKEN}"):
        url = f"ws://127.0.0.1:{port}/ws/runs/poisoned_bill?lane=notary&mode=cassette&{query}"
        try:
            with connect(url) as socket:
                while True:
                    socket.recv(timeout=5)
        except ConnectionClosed as closed:
            codes.append(-1 if closed.rcvd is None else closed.rcvd.code)
    get_list(port)
    return codes


def test_a_real_uvicorn_run_logs_no_token(detached: None) -> None:
    app = two_event_app()  # the app attaches the filter, nothing else does
    with capturing(UVICORN_LOGGERS) as capture, serving(app) as port:
        codes = talk(port)
        session_id = play_session(port)
    assert codes == [1000, 4400, 1000]
    text = capture.text()
    assert "/ws/runs/poisoned_bill" in text  # the servers did log the requests
    # Every covered logger really printed something in this run: the capture saw them all.
    assert {"uvicorn.access", "uvicorn.error"} <= capture.names
    assert any(name.startswith("websockets.") for name in capture.names)
    assert "token=[redacted]" in capture.text_of("uvicorn.access")  # the stray ?token= on HTTP
    assert "token=[redacted]" in capture.text_of("uvicorn.error")  # the WebSocket [accepted] line
    assert TOKEN not in text
    assert OTHER_TOKEN not in text
    assert BAD_TOKEN not in text  # a refused token is redacted as well
    assert "token=[redacted]" in text
    # The Hijacked Mode session id is a capability in the request path: the access log has the
    # route but never the id.
    assert "/playground/hijacked/[redacted]" in capture.text_of("uvicorn.access")
    assert session_id not in text


def test_control_a_real_uvicorn_run_prints_the_token_without_the_filter() -> None:
    """The same run with the filter off: uvicorn prints the query string, token included. This is
    the leak the filter closes."""
    app = two_event_app()
    with unredacted(), capturing(UVICORN_LOGGERS) as capture, serving(app) as port:
        codes = talk(port)
        session_id = play_session(port)
    assert codes == [1000, 4400, 1000]
    assert session_id in capture.text_of("uvicorn.access")  # the id leaks into the access log
    assert TOKEN in capture.text()
    assert BAD_TOKEN in capture.text()
    # ... and it leaks through each logger the filter covers, so each assertion above has teeth.
    assert TOKEN in capture.text_of("uvicorn.access")
    assert TOKEN in capture.text_of("uvicorn.error")
    assert any(
        TOKEN in capture.text_of(name) for name in capture.names if name.startswith("websockets.")
    )


def default_uvicorn_logging(access: io.StringIO, error: io.StringIO) -> dict[str, object]:
    """uvicorn's own logging configuration (its formatters, its logger layout), with the two
    handlers writing to the given buffers instead of the terminal."""
    config = copy.deepcopy(uvicorn.config.LOGGING_CONFIG)
    config["handlers"]["access"] = {
        "()": lambda: logging.StreamHandler(access),
        "formatter": "access",
    }
    config["handlers"]["default"] = {
        "()": lambda: logging.StreamHandler(error),
        "formatter": "default",
    }
    config["formatters"]["access"]["use_colors"] = False
    config["formatters"]["default"]["use_colors"] = False
    return config


@pytest.fixture
def uvicorn_loggers_restored() -> Generator[None]:
    """uvicorn's `dictConfig` replaces the handlers of its loggers; put them back afterwards."""
    names = ("uvicorn", "uvicorn.access", "uvicorn.error")
    saved = {
        name: (list(logging.getLogger(name).handlers), logging.getLogger(name).propagate)
        for name in names
    }
    yield
    for name, (handlers, propagate) in saved.items():
        logger = logging.getLogger(name)
        logger.handlers[:] = handlers
        logger.propagate = propagate


def test_every_request_is_logged_under_uvicorns_own_logging_config(
    detached: None, uvicorn_loggers_restored: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """With uvicorn's default formatters (the production setup) a redacted access line must still
    be written: the session id never appears, and no "Logging error" is printed."""
    access, error = io.StringIO(), io.StringIO()
    app = two_event_app()
    with serving(app, default_uvicorn_logging(access, error)) as port:
        session_id = play_session(port)
        get_list(port)
    lines = [line for line in access.getvalue().splitlines() if "/playground/hijacked" in line]
    # start, read the state, make a call: three lines, none lost to a formatter that raised
    assert len(lines) == 3
    assert all(line.endswith(" 200 OK") for line in lines)
    assert sum("/playground/hijacked/[redacted]" in line for line in lines) == 2
    assert session_id not in access.getvalue()
    assert "token=[redacted]" in access.getvalue()  # the stray ?token= of get_list
    assert TOKEN not in access.getvalue() + error.getvalue()
    assert "Logging error" not in capsys.readouterr().err
