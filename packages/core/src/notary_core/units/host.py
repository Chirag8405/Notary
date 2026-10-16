import re

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
