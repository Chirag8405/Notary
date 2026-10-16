"""Find URLs in outgoing text, so step 5 can check each host against the egress allowlist (A5)."""

import re
import unicodedata
from dataclasses import dataclass

from notary_core.units.host import canonicalize_host

_FLAGS = re.IGNORECASE

_SCHEME = re.compile(r"[a-z][a-z0-9+.\-]*://[^\s<>\"'\x60]+", _FLAGS)
_MARKDOWN_TARGET = re.compile(r"\]\(\s*([^)\s]+)", _FLAGS)
_PROTOCOL_RELATIVE = re.compile(
    r"(?<![:\w])//[a-z0-9][a-z0-9.\-]*[a-z0-9](?:[/?#][^\s<>\"']*)?", _FLAGS
)
_BARE_DOMAIN = re.compile(
    r"(?<![@\w.\-])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
    r"(?::\d+)?(?:[/?#][^\s<>\"']*)?",
    _FLAGS,
)

_TRAILING_PUNCTUATION = ".,;:!?"
_FILE_EXTENSIONS = frozenset(
    {"txt", "py", "md", "json", "js", "ts", "png", "jpg", "gif", "pdf", "csv", "log"}
)
"""A bare `name.ext` with one of these is a file name, not a host (heuristic)."""


@dataclass(frozen=True, slots=True)
class ExtractedUrl:
    raw: str
    """The URL text as found, after normalization."""
    host: str
    """Canonical host (`canonicalize_host(raw).value`)."""
    start: int
    """Offset into the NORMALIZED text."""
    end: int


def normalize_text(text: str) -> str:
    """NFKC, then drop format characters (zero-width joiners, tag characters). Keeps whitespace."""
    folded = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")


def _trim(text: str, start: int, end: int) -> tuple[int, int]:
    """Drop trailing sentence punctuation and unmatched closing brackets from `text[start:end]`."""
    while end > start:
        last = text[end - 1]
        piece = text[start:end]
        if (
            last in _TRAILING_PUNCTUATION
            or (last == ")" and piece.count("(") < piece.count(")"))
            or (last == "]" and piece.count("[") < piece.count("]"))
        ):
            end -= 1
        else:
            break
    return start, end


def _candidates(text: str) -> list[tuple[int, int]]:
    spans = [m.span() for m in _SCHEME.finditer(text)]
    spans += [m.span(1) for m in _MARKDOWN_TARGET.finditer(text)]
    spans += [m.span() for m in _PROTOCOL_RELATIVE.finditer(text)]
    spans += [m.span() for m in _BARE_DOMAIN.finditer(text)]
    return [_trim(text, start, end) for start, end in spans]


def _keep(raw: str, host: str, valid: bool) -> bool:
    has_scheme = "://" in raw or raw.startswith("//")
    if has_scheme:
        return True
    if not valid:
        return False
    return not ("/" not in raw and host.rsplit(".", 1)[-1] in _FILE_EXTENSIONS)


def _dedupe(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Keep the longest of any overlapping spans; result is ordered by start."""
    kept: list[tuple[int, int]] = []
    for start, end in sorted(spans, key=lambda s: (s[0], -(s[1] - s[0]))):
        if kept and start < kept[-1][1]:
            if end - start > kept[-1][1] - kept[-1][0]:
                kept[-1] = (start, end)
            continue
        kept.append((start, end))
    return kept


def extract_urls(text: str) -> tuple[ExtractedUrl, ...]:
    """Every URL in `text`: scheme URLs, markdown targets, `//host` and bare domains.

    Total: never raises. Offsets refer to `normalize_text(text)`.
    """
    normalized = normalize_text(text)
    candidates: list[tuple[int, int]] = []
    for start, end in _candidates(normalized):
        if end <= start:
            continue
        raw = normalized[start:end]
        host = canonicalize_host(raw)
        if _keep(raw, host.value, host.valid):
            candidates.append((start, end))
    found: list[ExtractedUrl] = []
    for start, end in _dedupe(candidates):
        raw = normalized[start:end]
        found.append(ExtractedUrl(raw, canonicalize_host(raw).value, start, end))
    return tuple(found)
