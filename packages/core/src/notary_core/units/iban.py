import re
import unicodedata

from notary_core.units.types import Canonical

_IBAN_SHAPE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}")
_MOD97_INPUT = re.compile(r"[A-Z0-9]{4,}")
_MAX_PASSES = 16


def iban_mod97_ok(iban: str) -> bool:
    """ISO 7064 mod-97 check; `iban` must already be canonical (uppercase, no spaces)."""
    if _MOD97_INPUT.fullmatch(iban) is None:
        return False
    rearranged = iban[4:] + iban[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def _normalize_once(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text)
    kept = "".join(
        ch
        for ch in folded
        if ch != "-"
        and not unicodedata.category(ch).startswith("Z")
        and unicodedata.category(ch) != "Cf"
    )
    return kept.upper()


def canonicalize_iban(raw: str) -> Canonical:
    # Stripping Cf characters can expose sequences that NFKC composes on a
    # further pass, so repeat until the value is stable.
    value = raw
    for _ in range(_MAX_PASSES):
        step = _normalize_once(value)
        if step == value:
            break
        value = step
    valid = _IBAN_SHAPE.fullmatch(value) is not None and iban_mod97_ok(value)
    return Canonical("iban", value, valid)
