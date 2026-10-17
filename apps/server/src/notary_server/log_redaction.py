"""Keep the read token out of the logs (#235).

uvicorn prints the request line, query string included, and so do the WebSocket library's
handshake lines, so a `?token=<value>` could reach an access log or an error log. One filter
rewrites every `token=<value>` to `token=[redacted]` in the rendered message (arguments included),
the exception text and the stack text of a record.

`attach_redaction()` puts it on `uvicorn.access`, `uvicorn.error` and the `websockets` tree. A
logger filter only sees the records of its own logger, and the library creates its child loggers
(`websockets.server`, ...) when uvicorn imports it, after the app was built. So the filter is also
applied from the log record factory to every record of those trees, which covers a child created
later. Calling it again changes nothing, so it holds under `--reload` and when many apps are made.
"""

import logging
import re
from collections.abc import Callable

REDACTED_TREES = ("uvicorn.access", "uvicorn.error", "websockets")
"""The loggers that can print a request line, and their children."""

_TOKEN_VALUE = re.compile(r"(token=)[^&\s\"'#]*", re.IGNORECASE)
_REDACTED = r"\1[redacted]"


def redact(text: str) -> str:
    """`token=<value>` becomes `token=[redacted]`; any other text is returned unchanged."""
    return _TOKEN_VALUE.sub(_REDACTED, text)


def has_token(text: str) -> bool:
    return _TOKEN_VALUE.search(text) is not None


class RedactTokenFilter(logging.Filter):
    """Redacts a record in place only when it holds a token, and never drops a record.

    The message is redacted AFTER it is rendered (`msg % args`): redacting the template would eat
    the placeholder of `"...?token=%s"` and leave its argument without a place. A record that
    holds a token gets the redacted text as its message and no arguments; a record without one is
    left exactly as it was (same message, same argument objects, no traceback rendered early)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            text = record.getMessage()
        except (TypeError, ValueError, KeyError):
            text = None  # a malformed call: leave it for logging to report as it always does
        if text is not None and has_token(text):
            record.msg = redact(text)
            record.args = None
        if record.exc_text is None and record.exc_info is not None and record.exc_info[0]:
            # Render the traceback to look at it; keep the text only when it holds the token (the
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
