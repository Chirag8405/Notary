"""Lookalike skeletons: collapse case, invisible characters and common confusables.

Known gap: CONFUSABLES is a small hand-written subset, not the full Unicode
confusables data. Lookalikes beyond this table are not normalized to the same
skeleton (threat model A8, "lookalikes beyond the normalizer").
"""

import unicodedata

from notary_core.models import DecisionUnit

CONFUSABLES: dict[str, str] = {
    "0": "o",
    "1": "l",
    "5": "s",
    "i": "l",
    "|": "l",
    "\u0430": "a",  # Cyrillic Cyrillic Small Letter A
    "\u0435": "e",  # Cyrillic Cyrillic Small Letter Ie
    "\u043e": "o",  # Cyrillic Cyrillic Small Letter O
    "\u0440": "p",  # Cyrillic Cyrillic Small Letter Er
    "\u0441": "c",  # Cyrillic Cyrillic Small Letter Es
    "\u0443": "y",  # Cyrillic Cyrillic Small Letter U
    "\u0445": "x",  # Cyrillic Cyrillic Small Letter Ha
    "\u0456": "i",  # Cyrillic Cyrillic Small Letter Byelorussian-Ukrainian I
    "\u0458": "j",  # Cyrillic Cyrillic Small Letter Je
    "\u0455": "s",  # Cyrillic Cyrillic Small Letter Dze
    "\u0501": "d",  # Cyrillic Cyrillic Small Letter Komi De
    "\u04bb": "h",  # Cyrillic Cyrillic Small Letter Shha
    "\u051b": "q",  # Cyrillic Cyrillic Small Letter Qa
    "\u03bf": "o",  # Greek Greek Small Letter Omicron
    "\u03b1": "a",  # Greek Greek Small Letter Alpha
    "\u03bd": "v",  # Greek Greek Small Letter Nu
    "\u03c1": "p",  # Greek Greek Small Letter Rho
    "\u03b9": "l",  # Greek Greek Small Letter Iota
    "\u03ba": "k",  # Greek Greek Small Letter Kappa
    "\u03c4": "t",  # Greek Greek Small Letter Tau
    "\u03c5": "u",  # Greek Greek Small Letter Upsilon
}

# Applied after the single-character mapping, pair by pair, left to right.
MULTI_CONFUSABLES: tuple[tuple[str, str], ...] = (("rn", "m"), ("vv", "w"), ("cl", "d"))

_MAX_PASSES = 16
_EXACT_UNITS: frozenset[DecisionUnit] = frozenset({"iban", "amount"})


def _reduced_step(s: str) -> str:
    folded = unicodedata.normalize("NFKC", s).casefold()
    return "".join(
        ch
        for ch in folded
        if unicodedata.category(ch) != "Cf" and not unicodedata.category(ch).startswith("Z")
    )


def _full_step(s: str) -> str:
    mapped = "".join(CONFUSABLES.get(ch, ch) for ch in _reduced_step(s))
    for old, new in MULTI_CONFUSABLES:
        mapped = mapped.replace(old, new)
    return mapped


def normalize_for_match(unit: DecisionUnit, s: str) -> str:
    """Skeleton of `s` for near-match comparison; a fixed point of the unit's step.

    iban and amount keep digits and letters significant, so they use only NFKC,
    casefold and invisible-character removal.
    """
    step = _reduced_step if unit in _EXACT_UNITS else _full_step
    value = s
    for _ in range(_MAX_PASSES):
        nxt = step(value)
        if nxt == value:
            break
        value = nxt
    return value


def osa_distance(a: str, b: str, limit: int) -> int:
    """Optimal string alignment distance (restricted Damerau-Levenshtein).

    An adjacent transposition costs 1 and no substring is edited twice, so this
    is not a true metric (no triangle inequality). Returns `limit + 1` when the
    distance exceeds `limit`, and the exact distance otherwise.
    """
    limit = max(limit, 0)
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    two_back: list[int] = []
    previous = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        current = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            best = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                best = min(best, two_back[j - 2] + 1)
            current[j] = best
        # A transposition reads the row two back, so one row above the limit is not enough.
        if min(current) > limit and min(previous) > limit:
            return limit + 1
        two_back, previous = previous, current
    return min(previous[len(b)], limit + 1)
