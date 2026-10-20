import re
import unicodedata

from notary_core.units._public_suffixes import ICANN_RULES, PRIVATE_RULES
from notary_core.units.types import Canonical

# Rules of the pinned Public Suffix List, split by kind. Built once at import from the embedded
# frozensets (pure data; nothing is read from disk or the network). Both the ICANN and the
# PRIVATE section count: a private suffix such as github.io is a public suffix for egress.
_RULES: frozenset[str] = ICANN_RULES | PRIVATE_RULES
_EXCEPTIONS: frozenset[str] = frozenset(r[1:] for r in _RULES if r.startswith("!"))
_WILDCARDS: frozenset[str] = frozenset(r[2:] for r in _RULES if r.startswith("*."))
_SUFFIXES: frozenset[str] = frozenset(r for r in _RULES if r[0] not in "!*")

_OCTET = r"(?:0|[1-9][0-9]{0,2})"
_IPV4 = re.compile(rf"{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}")
_IPV6_INNER = re.compile(r"[0-9a-f:]+")
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_NUMERIC_LAST_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*")
_URL = re.compile(
    r"(?:(?:[a-z][a-z0-9+.\-]*:)?//)?(?:[^/?#]*@)?(\[[0-9a-f:]+\]|[^/?#:]+)(?::\d*)?(?:[/?#].*)?",
    re.IGNORECASE | re.DOTALL,
)
_DOT_LIKE = {"。": ".", "｡": "."}
_BROWSER_DELETED = frozenset({"\t", "\n", "\r"})
_MAX_HOST_LEN = 253
_MAX_OCTET = 255
_MAX_GROUP_LEN = 4
_MAX_GROUPS = 8


def is_strict_ipv4(host: str) -> bool:
    if _IPV4.fullmatch(host) is None:
        return False
    return all(int(octet) <= _MAX_OCTET for octet in host.split("."))


def is_ipv6_literal(host: str) -> bool:
    """Bracketed IPv6 literal, checked by hand; no compression or expansion."""
    if len(host) < 2 or not host.startswith("[") or not host.endswith("]"):
        return False
    inner = host[1:-1]
    if _IPV6_INNER.fullmatch(inner) is None:
        return False
    if inner.count(":") < 2 or ":::" in inner or inner.count("::") > 1:
        return False
    groups = [group for group in inner.split(":") if group]
    return len(groups) <= _MAX_GROUPS and all(len(group) <= _MAX_GROUP_LEN for group in groups)


def _ace(label: str) -> str:
    if label.isascii():
        return label
    try:
        return "xn--" + label.encode("punycode").decode("ascii")
    except UnicodeError:
        return label


def _suffix_length(labels: list[str]) -> int:
    """Number of trailing labels of `labels` that form the public suffix (PSL algorithm).

    An exception rule prevails over everything and its suffix is the rule minus its first
    label; otherwise the longest matching suffix or wildcard rule wins; with no match the
    implicit "*" rule makes the last label the suffix.
    """
    count = len(labels)
    for start in range(count):
        if ".".join(labels[start:]) in _EXCEPTIONS:
            return count - start - 1
    for start in range(count):
        if ".".join(labels[start:]) in _SUFFIXES or ".".join(labels[start + 1 :]) in _WILDCARDS:
            return count - start
    return 1


def registrable_domain(host: str) -> str:
    """Registrable domain (public suffix plus one label) of a host, by the Public Suffix List.

    The input is normally a canonical host from `canonicalize_host`; as defence in depth the
    function also lowercases, drops one trailing dot and converts non-ASCII labels to punycode,
    and returns that normalized form. Both PSL sections apply, so `a.github.io` and
    `b.github.io` are different registrable domains and an egress entry for one tenant does
    not admit another. IP literals are returned unchanged. A host that is itself a public
    suffix (`co.uk`, `github.io`) or a single label (`localhost`) has no registrable domain
    and is returned as is, so an allowlist entry for it matches only that exact host, never
    its subdomains.
    """
    if is_strict_ipv4(host) or host.startswith("["):
        return host
    labels = [_ace(label) for label in host.lower().removesuffix(".").split(".")]
    keep = _suffix_length(labels) + 1
    return ".".join(labels[-keep:])


def _preprocess(raw: str) -> str:
    folded = unicodedata.normalize("NFKC", raw)
    dotted = "".join(_DOT_LIKE.get(ch, ch) for ch in folded)
    kept = "".join(
        ch
        for ch in dotted
        if ch not in _BROWSER_DELETED
        and not unicodedata.category(ch).startswith("Z")
        and unicodedata.category(ch) != "Cf"
    )
    return kept.strip().replace("\\", "/")


def _host_valid(host: str) -> bool:
    if len(host) > _MAX_HOST_LEN:
        return False
    if is_ipv6_literal(host) or is_strict_ipv4(host):
        return True
    if host.startswith("["):
        return False
    labels = host.split(".")
    if _NUMERIC_LAST_LABEL.fullmatch(labels[-1]) is not None:
        return False
    return all(_LABEL.fullmatch(label) is not None for label in labels)


def canonicalize_host(raw: str) -> Canonical:
    """Host of a URL or bare host, lowercase and ASCII; userinfo, port and path dropped."""
    text = _preprocess(raw)
    match = _URL.fullmatch(text)
    # "scheme:///x" has an empty authority; the pattern alone would read the scheme as the host.
    if match is None or text[match.end(1) :].startswith("://"):
        return Canonical("url_host", text.lower(), False)

    host = match.group(1).lower().removesuffix(".")
    if "%" in host:
        return Canonical("url_host", host, False)
    if host.startswith("["):
        return Canonical("url_host", host, _host_valid(host))
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return Canonical("url_host", host, False)
    return Canonical("url_host", host, _host_valid(host))
