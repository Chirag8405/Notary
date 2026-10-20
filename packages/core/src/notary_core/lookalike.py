"""Lookalike skeletons: collapse case, invisible characters and confusable characters.

The single-character table is generated from Unicode's confusables.txt (UTS #39); see
`_confusables_data.py` and `packages/core/scripts/gen_confusables.py`. NFKC already folds
fullwidth forms and mathematical alphanumerics before the table is consulted. What stays
outside it is a limit of the data, not of this file: pairs that need context (`rn` for
`m`, handled below), diacritics and characters that Unicode does not list (threat model
A8, "lookalikes beyond the normalizer").
"""

import difflib
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass

from notary_core._confusables_data import SKELETON
from notary_core.models import DecisionUnit

# Not in Unicode's data: digit lookalikes the original table carried (5 reads as s).
LOCAL_CONFUSABLES: dict[str, str] = {"5": "s"}

CONFUSABLES: dict[str, str] = {**SKELETON, **LOCAL_CONFUSABLES}

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


@dataclass(frozen=True, slots=True)
class LookalikeConfig:
    fold_confusables: bool
    max_edits: int
    min_length_for_edits: int  # below this length only confusable-equality counts
    require_equal_length: bool


# Thresholds are judgment calls kept as data; tuning needs no logic change.
LOOKALIKE_CONFIG: dict[DecisionUnit, LookalikeConfig] = {
    "iban": LookalikeConfig(False, 2, 15, True),
    "email": LookalikeConfig(True, 1, 8, False),
    "url_host": LookalikeConfig(True, 1, 8, False),
    "identifier": LookalikeConfig(True, 1, 8, False),
    "amount": LookalikeConfig(False, 0, 0, False),  # never a lookalike
}


@dataclass(frozen=True, slots=True)
class LookalikeMatch:
    known: str  # the known canonical value that was matched
    distance: int  # OSA distance between the NORMALIZED forms
    confusable_equal: bool  # normalized forms identical although canonical forms differ
    differing_positions: tuple[int, ...]  # indices in `candidate` that differ from `known`


def _decode_punycode(text: str) -> str:
    """Back to Unicode when `text` holds punycode labels; unchanged on any decode error."""
    if "xn--" not in text:
        return text
    try:
        return text.encode("ascii").decode("idna")
    except UnicodeError:
        return text


def _skeleton(unit: DecisionUnit, s: str) -> str:
    # Canonical hosts and email domains are punycode, so decode them first or the
    # Cyrillic and Greek entries of CONFUSABLES could never apply.
    if unit == "url_host":
        s = _decode_punycode(s)
    elif unit == "email":
        local, at, domain = s.rpartition("@")
        s = local + at + _decode_punycode(domain)
    return normalize_for_match(unit, s)


def _differing_positions(known: str, candidate: str) -> tuple[int, ...]:
    """Indices in `candidate` that differ from `known`, sorted and unique."""
    if len(candidate) == len(known):
        return tuple(i for i, (x, y) in enumerate(zip(known, candidate, strict=True)) if x != y)
    if not candidate:
        return ()
    positions: set[int] = set()
    matcher = difflib.SequenceMatcher(None, known, candidate, autojunk=False)
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if j2 > j1:
            positions.update(range(j1, j2))
        else:
            # Pure deletion: the candidate lacks characters; still mark the spot.
            positions.add(min(j1, len(candidate) - 1))
    return tuple(sorted(positions))


def is_lookalike(unit: DecisionUnit, candidate: str, known: Sequence[str]) -> LookalikeMatch | None:
    """Closest known value that `candidate` imitates, or None. Inputs are canonical strings."""
    config = LOOKALIKE_CONFIG[unit]
    if unit == "amount":
        return None
    a = _skeleton(unit, candidate)
    best: LookalikeMatch | None = None
    for k in known:
        if candidate == k:
            continue
        b = _skeleton(unit, k)
        if a == b:
            distance, confusable_equal = 0, True
        elif (
            len(a) >= config.min_length_for_edits
            and (not config.require_equal_length or len(a) == len(b))
            and abs(len(a) - len(b)) <= config.max_edits
        ):
            distance = osa_distance(a, b, config.max_edits)
            if distance > config.max_edits:
                continue
            confusable_equal = False
        else:
            continue
        if best is None or distance < best.distance:
            best = LookalikeMatch(k, distance, confusable_equal, _differing_positions(k, candidate))
    return best


def nearest_known(
    unit: DecisionUnit, candidate: str, known: Sequence[str]
) -> tuple[str, tuple[int, ...]] | None:
    """Closest known value at any distance, with the differing positions for the diff card."""
    a = _skeleton(unit, candidate)
    best: str | None = None
    best_distance = 0
    for k in known:
        b = _skeleton(unit, k)
        distance = osa_distance(a, b, max(len(a), len(b)))
        if best is None or distance < best_distance:
            best, best_distance = k, distance
    if best is None:
        return None
    return best, _differing_positions(best, candidate)
