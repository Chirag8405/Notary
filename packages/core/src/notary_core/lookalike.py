"""Lookalike skeletons: collapse case, invisible characters and common confusables.

Known gap: CONFUSABLES is a small hand-written subset, not the full Unicode
confusables data. Lookalikes beyond this table are not normalized to the same
skeleton (threat model A8, "lookalikes beyond the normalizer").
"""

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
