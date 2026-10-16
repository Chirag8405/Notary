import re
import unicodedata

from notary_core.units.types import Canonical

_WHITESPACE = re.compile(r"\s+")
_MAX_PASSES = 16


def _normalize_once(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text)
    kept = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")
    return _WHITESPACE.sub(" ", kept).strip().casefold()


def canonicalize_identifier(raw: str) -> Canonical:
    # Each step can expose input for the next (dropped Cf characters, casefold
    # expansions), so repeat until the value is stable.
    value = raw
    for _ in range(_MAX_PASSES):
        step = _normalize_once(value)
        if step == value:
            break
        value = step
    return Canonical("identifier", value, value != "")
