"""Output Guard: show the user where each sentence of the final answer came from (A13).

The agent's answer is split into sentences. Each sentence is labeled by provenance (user, ledger,
untrusted or model), untrusted text is shown quoted and attributed, and links are defanged unless
their host is allowed. This is display logic only: it surfaces text-to-text deception, it does not
prevent it. It never decides an effect, calls an LLM, or fetches or resolves a URL.

Known limits, on purpose: the phone and account regexes are simple (they also match things like a
date such as 2026-12-05 inside an untrusted sentence, and the IBAN pattern is case-sensitive on the
normalized text), so a miss or a false flag only changes a warning. Sentence splitting is naive
(an abbreviation ends a sentence). A subtle factual bias in a summary is not detectable here.
"""

import re
from typing import Literal

from notary_core.models import (
    NotaryModel,
)

SentenceSource = Literal["user", "ledger", "untrusted", "model"]

_NEWLINE = re.compile(r"\r\n|\n|\r")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_HTTP_SCHEME = re.compile(r"http(?=s?://)", re.IGNORECASE)
_SCHEME_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")
_PHONE = re.compile(r"\+?\d[\d ().-]{7,}\d")
_ACCOUNT = re.compile(r"[A-Z]{2}\d{2}[A-Z0-9 ]{10,30}|\b\d{8,}\b")

FLAG_URL = "untrusted_url"
FLAG_PHONE = "untrusted_phone"
FLAG_ACCOUNT = "untrusted_account"


class GuardedSentence(NotaryModel):
    index: int
    text: str
    """The sentence exactly as the agent wrote it."""
    source: SentenceSource
    value_ids: tuple[str, ...]
    """Stored values the sentence quotes, sorted."""
    shown: str
    """What the UI displays: normalized, URLs defanged, untrusted text quoted and attributed."""
    defanged: tuple[str, ...]
    """URLs defanged in `shown`, in order of appearance."""
    flags: tuple[str, ...]
    """A subset of `untrusted_url`, `untrusted_phone`, `untrusted_account`, in that order."""


class GuardedAnswer(NotaryModel):
    sentences: tuple[GuardedSentence, ...]
    notices: tuple[str, ...]


def split_sentences(answer: str) -> tuple[str, ...]:
    """Split per line, then after `.`, `!` or `?` plus whitespace; pieces are stripped, never
    rewritten, and blank pieces are dropped."""
    pieces: list[str] = []
    for line in _NEWLINE.split(answer):
        for piece in _SENTENCE_END.split(line):
            stripped = piece.strip()
            if stripped:
                pieces.append(stripped)
    return tuple(pieces)


def defang(url: str) -> str:
    """Make a link unclickable: `http` becomes `hxxp` and every `.` of the authority `[.]`.

    The authority is everything after the scheme up to the first `/`, `?` or `#` (userinfo, host
    and port); path, query and fragment are kept byte for byte. Total: never raises.
    """
    head = "hxxp" + url[4:] if _HTTP_SCHEME.match(url) else url
    scheme = _SCHEME_PREFIX.match(head)
    if scheme is not None:
        start = scheme.end()
    elif head.startswith("//"):
        start = 2
    else:
        start = 0
    end = len(head)
    for index in range(start, len(head)):
        if head[index] in "/?#":
            end = index
            break
    return head[:start] + head[start:end].replace(".", "[.]") + head[end:]
