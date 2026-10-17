"""Keep the read token and the Hijacked Mode session id out of the logs (#235, #242).

uvicorn prints the request line, query string included, and so do the WebSocket library's
handshake lines, so a `?token=<value>` could reach an access log or an error log. One filter
rewrites every `token=<value>` to `token=[redacted]` in the rendered message (arguments included),
the exception text and the stack text of a record. A Hijacked Mode session id is a capability that
lives in the request path (`/playground/hijacked/<id>/calls`), so the same filter rewrites it to
`/playground/hijacked/[redacted]`.

`attach_redaction()` puts it on `uvicorn.access`, `uvicorn.error` and the `websockets` tree. A
logger filter only sees the records of its own logger, and the library creates its child loggers
(`websockets.server`, ...) when uvicorn imports it, after the app was built. So the filter is also
applied from the log record factory to every record of those trees, which covers a child created
later. Calling it again changes nothing, so it holds under `--reload` and when many apps are made.
"""

import logging
import re
from collections.abc import Callable, Mapping

REDACTED_TREES = ("uvicorn.access", "uvicorn.error", "websockets")
"""The loggers that can print a request line, and their children."""

_TOKEN_VALUE = re.compile(r"(token=)(?!\[redacted\])[^&\s\"'#]*", re.IGNORECASE)
"""`token=<value>`, but not a value that is already `[redacted]` (so redacting twice is a no-op, and
a record that was redacted is not mistaken for a secret one)."""
_SESSION_PATH = re.compile(r"(/playground/hijacked/)[A-Za-z0-9_-]+")
_REDACTED = r"\1[redacted]"


def redact(text: str) -> str:
    """`token=<value>` becomes `token=[redacted]` and `/playground/hijacked/<id>` becomes
    `/playground/hijacked/[redacted]`; any other text is returned unchanged."""
    return _SESSION_PATH.sub(_REDACTED, _TOKEN_VALUE.sub(_REDACTED, text))


def has_token(text: str) -> bool:
    """Whether the text holds something `redact` would rewrite."""
    return _TOKEN_VALUE.search(text) is not None or _SESSION_PATH.search(text) is not None


_TOKEN_IN_TEMPLATE = re.compile(r"(token=)(?!%|\[redacted\])[^&\s\"'#]*", re.IGNORECASE)
"""Like `_TOKEN_VALUE`, but it leaves `token=%s` alone: the value of a placeholder is redacted in
the arguments, and eating the placeholder would leave its argument without a place."""


def _redact_template(text: str) -> str:
    return _SESSION_PATH.sub(_REDACTED, _TOKEN_IN_TEMPLATE.sub(_REDACTED, text))


def _redact_arg(value: object) -> object:
    """The argument itself unless it prints a secret (by `str` or `repr`)."""
    if isinstance(value, str):
        return redact(value) if has_token(value) else value
    if isinstance(value, int | float | bool) or value is None:
        return value
    for text in (str(value), repr(value)):  # `%s` and `%r` print different things
        if has_token(text):
            return redact(text)
    return value


def _redact_args(
    args: tuple[object, ...] | Mapping[str, object] | None,
) -> tuple[object, ...] | Mapping[str, object] | None:
    """The same object when no argument holds a secret, else a copy of the same shape: a formatter
    may rely on the number and the position of the arguments (uvicorn's `AccessFormatter` unpacks
    five)."""
    if args is None:
        return None
    if isinstance(args, Mapping):
        changed = {key: _redact_arg(value) for key, value in args.items()}
        return changed if any(changed[key] is not args[key] for key in args) else args
    changed_tuple = tuple(_redact_arg(value) for value in args)
    same = all(new is old for new, old in zip(changed_tuple, args, strict=True))
    return args if same else changed_tuple


class RedactTokenFilter(logging.Filter):
    """Redacts a record in place only when it holds a secret, and never drops a record.

    The arguments are redacted one by one and keep their shape and position, so a formatter that
    unpacks them (uvicorn's access log) still works; the template is redacted only for a literal
    secret, never for a placeholder. Then the rendered message is checked once more: a secret that
    exists only once the template and the arguments are joined is redacted in the rendered text
    (the message then has no arguments). A record without a secret is left exactly as it was (same
    message, same argument objects, no traceback rendered early)."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            if has_token(record.msg):
                record.msg = _redact_template(record.msg)
        elif has_token(str(record.msg)):
            record.msg = redact(str(record.msg))
        record.args = _redact_args(record.args)
        try:
            text = record.getMessage()
        except (TypeError, ValueError, KeyError):
            text = None  # a malformed call: leave it for logging to report as it always does
        if text is not None and has_token(text):
            record.msg = redact(text)
            record.args = None
        if record.exc_text is None and record.exc_info is not None and record.exc_info[0]:
            # Render the traceback to look at it; keep the text only when it holds a secret (the
            # formatter would render the same text later and cache it here).
            rendered = logging.Formatter().formatException(record.exc_info)
            if has_token(rendered):
                record.exc_text = redact(rendered)
        elif record.exc_text and has_token(record.exc_text):
            record.exc_text = redact(record.exc_text)
        if record.stack_info and has_token(record.stack_info):
            record.stack_info = redact(record.stack_info)
        return True


FILTER = RedactTokenFilter()


def in_redacted_tree(name: str) -> bool:
    return any(name == tree or name.startswith(tree + ".") for tree in REDACTED_TREES)


class RedactingFactory:
    """A log record factory that redacts the records of `REDACTED_TREES`."""

    def __init__(self, inner: Callable[..., logging.LogRecord]) -> None:
        self.inner = inner

    def __call__(self, *args: object, **kwargs: object) -> logging.LogRecord:
        record = self.inner(*args, **kwargs)
        if in_redacted_tree(record.name):
            FILTER.filter(record)
        return record


def attach_redaction() -> None:
    """Put the filter on every logger of the trees and on the record factory, once."""
    for name in REDACTED_TREES:
        logging.getLogger(name).addFilter(FILTER)  # addFilter ignores a filter already added
    for name, logger in list(logging.Logger.manager.loggerDict.items()):
        if isinstance(logger, logging.Logger) and in_redacted_tree(name):
            logger.addFilter(FILTER)
    current = logging.getLogRecordFactory()
    if not isinstance(current, RedactingFactory):
        logging.setLogRecordFactory(RedactingFactory(current))
