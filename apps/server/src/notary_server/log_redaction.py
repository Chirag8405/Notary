"""Keep the read token out of the logs (#235).

uvicorn prints the request line, query string included, and so do the WebSocket library's
handshake lines, so a `?token=<value>` could reach an access log or an error log. One filter
rewrites every `token=<value>` to `token=[redacted]` in the message, the arguments, the exception
text and the stack text of a record.

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

_TOKEN_VALUE = re.compile(r"(token=)[^&\s\"'#]*", re.IGNORECASE)
_REDACTED = r"\1[redacted]"


def redact(text: str) -> str:
    """`token=<value>` becomes `token=[redacted]`; any other text is returned unchanged."""
    return _TOKEN_VALUE.sub(_REDACTED, text)


def _redact_arg(value: object) -> object:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, int | float | bool) or value is None:
        return value
    for text in (str(value), repr(value)):  # `%s` and `%r` print different things
        if _TOKEN_VALUE.search(text):
            return redact(text)
    return value


class RedactTokenFilter(logging.Filter):
    """Redacts in place and never drops a record."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not isinstance(record.msg, str) and _TOKEN_VALUE.search(str(record.msg)):
            record.msg = str(record.msg)
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        record.args = _redact_args(record.args)
        if record.exc_text is None and record.exc_info is not None and record.exc_info[0]:
            # The formatter would render the traceback later and cache it here; render it now so
            # the redaction below applies to it.
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        return True


def _redact_args(
    args: tuple[object, ...] | Mapping[str, object] | None,
) -> tuple[object, ...] | Mapping[str, object] | None:
    if args is None:
        return None
    if isinstance(args, Mapping):
        return {key: _redact_arg(value) for key, value in args.items()}
    return tuple(_redact_arg(value) for value in args)


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
