import re
import unicodedata

from notary_core.units.types import Canonical

# Small embedded list. Unknown multi-part suffixes (for example com.sg) are
# deliberately treated as two-label domains (documented known gap); extending
# the list later is a data change, not a logic change.
MULTIPART_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "co.jp",
        "co.in",
        "com.br",
        "com.cn",
        "com.mx",
        "co.za",
    }
)

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


def registrable_domain(host: str) -> str:
    """Approximate registrable domain of an already canonical host."""
    if is_strict_ipv4(host) or host.startswith("["):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTIPART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


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
