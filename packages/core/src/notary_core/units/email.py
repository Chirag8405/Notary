import re
import unicodedata

from notary_core.units.types import Canonical

_DISPLAY_NAME = re.compile(r"^.*<([^<>]+)>\s*$")
_LOCAL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_{|}~-]+")
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_MAX_LOCAL = 64


def _clean(raw: str) -> str:
    folded = unicodedata.normalize("NFKC", raw)
    kept = "".join(
        ch
        for ch in folded
        if not unicodedata.category(ch).startswith("Z") and unicodedata.category(ch) != "Cf"
    )
    return kept.strip()


def canonicalize_email(raw: str) -> Canonical:
    text = _clean(raw)
    angle = _DISPLAY_NAME.match(text)
    if angle is not None:
        text = angle.group(1)
    text = text.lower()

    parts = text.split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return Canonical("email", text, False)
    local, domain = parts

    ascii_ok = True
    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        ascii_ok = False

    valid = (
        ascii_ok
        and len(local) <= _MAX_LOCAL
        and _LOCAL.fullmatch(local) is not None
        and "." in domain
        and all(_LABEL.fullmatch(label) is not None for label in domain.split("."))
    )
    return Canonical("email", f"{local}@{domain}", valid)
