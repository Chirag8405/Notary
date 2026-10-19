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
from collections.abc import Mapping, Sequence
from typing import Literal

from notary_core.ledger import entries_for
from notary_core.models import (
    LedgerEntry,
    LedgerOrigin,
    NotaryModel,
    Origin,
    ResolvedValue,
    ToolOrigin,
    UserOrigin,
)
from notary_core.resolver import MIN_MATCH_LEN
from notary_core.runner import FilterFlag
from notary_core.units import canonicalize
from notary_core.urls import ExtractedUrl, extract_urls, normalize_text

SentenceSource = Literal["user", "ledger", "untrusted", "model"]

_NEWLINE = re.compile(r"\r\n|\n|\r")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_HTTP_SCHEME = re.compile(r"http(?=s?://)", re.IGNORECASE)
_SCHEME_TAIL = re.compile(r"://\S*")
_NESTED_AUTHORITY = re.compile(r"(?<=:)//[^/?#]*")
_INNER_DOT = re.compile(r"(?<=[A-Za-z0-9\-])\.(?=[A-Za-z]{2})")
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
    and port). Every further `http(s)://` in the rest (glued text such as `http://x.yhttp://x.y`
    or a link in the query) gets the same treatment: `hxxp(s)://` and `[.]` in the authority that
    follows its `//`. A dot followed by two letters in the path, query or
    fragment becomes `[.]` too (a bare domain glued behind a link); the rest is kept byte for byte.
    Total: never raises.
    """
    head = _HTTP_SCHEME.sub("hxxp", url)
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
    # Start one character early so the lookbehind sees the `:` of a glued `://`.
    glued = _NESTED_AUTHORITY.sub(lambda m: m.group().replace(".", "[.]"), head[max(end - 1, 0) :])
    rest = _INNER_DOT.sub("[.]", glued[1:] if end > 0 else glued)
    return head[:start] + head[start:end].replace(".", "[.]") + rest


# --- guard_answer


def _origin_text(origin: Origin) -> str:
    if isinstance(origin, ToolOrigin):
        return f"tool:{origin.name}"
    return origin.kind


def _needles(value: ResolvedValue) -> tuple[str, ...]:
    """Normalized, casefolded texts of a value that count as quoting it: the whole text, or any
    one of its sentences. Each must be at least `MIN_MATCH_LEN` long after normalization."""
    texts = [value.text, *split_sentences(value.text)]
    found: list[str] = []
    for text in texts:
        needle = normalize_text(text).casefold().strip()
        if len(needle) >= MIN_MATCH_LEN and needle not in found:
            found.append(needle)
    return tuple(found)


def _is_ledger_value(value: ResolvedValue, ledger: Sequence[LedgerEntry]) -> bool:
    if isinstance(value.ref.label.origin, LedgerOrigin):
        return True
    return any(canonicalize(e.unit, value.text).value == e.canonical for e in ledger)


def _source(quoted: Sequence[ResolvedValue], ledger: Sequence[LedgerEntry]) -> SentenceSource:
    if any(v.ref.label.integrity == "untrusted" for v in quoted):
        return "untrusted"
    if any(_is_ledger_value(v, ledger) for v in quoted):
        return "ledger"
    if any(isinstance(v.ref.label.origin, UserOrigin) for v in quoted):
        return "user"
    return "model"


def _defanged_text(
    normalized: str, urls: Sequence[ExtractedUrl], allowed: frozenset[str]
) -> tuple[str, tuple[str, ...]]:
    """Replace the non-allowed URLs from the END backwards, so earlier offsets stay valid."""
    limit = len(normalized)
    text = normalized
    replaced: list[str] = []
    starts = sorted(u.start for u in urls)
    for url in sorted(
        (u for u in urls if u.host not in allowed), key=lambda u: u.start, reverse=True
    ):
        if url.end > limit:
            continue
        # A bare-domain match can stop at a glued `://` (`1234567.http://x.y` matches only
        # `1234567.http`): defang the rest of the word too, up to the next URL.
        bound = min([limit, *(b for b in starts if b > url.start)])
        tail = _SCHEME_TAIL.match(text[:bound], url.end)
        end = tail.end() if tail is not None else url.end
        text = text[: url.start] + defang(text[url.start : end]) + text[end:]
        limit = url.start
        replaced.append(url.raw)
    # `defang` keeps paths byte for byte, so a link nested in another link's path (glued text such
    # as `http://a.bhttp://c.d`) would survive the pass above: defang the remaining copies too.
    for raw in dict.fromkeys(replaced):
        text = text.replace(raw, defang(raw))
    return text, tuple(reversed(replaced))


def guard_answer(
    answer: str,
    values: Mapping[str, ResolvedValue],
    ledger: Sequence[LedgerEntry],
    *,
    allowed_hosts: Sequence[str] = (),
    flags: Sequence[FilterFlag] = (),
) -> GuardedAnswer:
    """Label every sentence of `answer` by provenance and defang links that are not allowed."""
    stored = sorted(values.values(), key=lambda v: v.ref.id)
    needles = {v.ref.id: _needles(v) for v in stored}
    allowed = frozenset(
        host
        for host in (
            *(canonicalize("url_host", h).value for h in allowed_hosts),
            *(e.canonical for e in entries_for(ledger, "url_host")),
        )
        if host
    )
    sentences: list[GuardedSentence] = []
    for index, text in enumerate(split_sentences(answer)):
        normalized = normalize_text(text)
        folded = normalized.casefold()
        quoted = [v for v in stored if any(n in folded for n in needles[v.ref.id])]
        source = _source(quoted, ledger)
        shown_text, defanged = _defanged_text(normalized, extract_urls(text), allowed)
        found: list[str] = []
        if defanged:
            found.append(FLAG_URL)
        if source == "untrusted":
            if _PHONE.search(normalized):
                found.append(FLAG_PHONE)
            if _ACCOUNT.search(normalized):
                found.append(FLAG_ACCOUNT)
        shown = shown_text
        if source == "untrusted":
            first = next(v for v in quoted if v.ref.label.integrity == "untrusted")
            shown = f'[untrusted: {_origin_text(first.ref.label.origin)}] "{shown_text}"'
        sentences.append(
            GuardedSentence(
                index=index,
                text=text,
                source=source,
                value_ids=tuple(v.ref.id for v in quoted),
                shown=shown,
                defanged=defanged,
                flags=tuple(found),
            )
        )
    quoted_ids = {i for s in sentences for i in s.value_ids}
    notices: list[str] = []
    for flag in flags:
        notice = (
            f"untrusted content ({_flag_origin(flag, stored, quoted_ids)}) contained text "
            f"flagged as {flag.label}; it is shown quoted and was not treated as a request "
            "from you"
        )
        if notice not in notices:
            notices.append(notice)
    return GuardedAnswer(sentences=tuple(sentences), notices=tuple(notices))


def _flag_origin(flag: FilterFlag, stored: Sequence[ResolvedValue], quoted_ids: set[str]) -> str:
    """Origin of the value a flag points at. `FilterFlag.field` is a tool-result field name
    (`body`), so it matches a stored value id ending in `.body` (or the id itself); a value some
    sentence quotes is preferred, and none at all gives `unknown`."""
    matches = [v for v in stored if v.ref.id == flag.field or v.ref.id.endswith("." + flag.field)]
    if not matches:
        return "unknown"
    chosen = next((v for v in matches if v.ref.id in quoted_ids), matches[0])
    return _origin_text(chosen.ref.label.origin)


def render_guarded(guarded: GuardedAnswer) -> str:
    """The sentences joined by single spaces, then each notice on its own `notice: ` line."""
    lines: list[str] = []
    if guarded.sentences:
        lines.append(" ".join(s.shown for s in guarded.sentences))
    lines.extend(f"notice: {notice}" for notice in guarded.notices)
    return "\n".join(lines)
