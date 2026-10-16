import re
import unicodedata
from dataclasses import dataclass
from decimal import Decimal

# Currency codes are not validated against an ISO list (known gap): any three
# uppercase ASCII letters count as a code.
_SYMBOLS: dict[str, str] = {"€": "EUR", "$": "USD", "£": "GBP", "¥": "JPY"}
_MARKER = r"(?:([A-Z]{3})|([€$£¥]))"
_LEADING_MARKER = re.compile(_MARKER + r"\s*")
_TRAILING_MARKER = re.compile(r"\s*" + _MARKER + r"$")
_NUMERIC_CHARS = re.compile(r"[0-9.,]+")
_MAX_NUMERIC_LEN = 64


@dataclass(frozen=True, slots=True)
class CanonicalAmount:
    value: Decimal | None  # None when unparseable
    currency: str | None  # ISO-style code, e.g. "EUR"; None if absent
    valid: bool


_INVALID = CanonicalAmount(value=None, currency=None, valid=False)


def _marker_currency(match: re.Match[str]) -> str:
    code, symbol = match.group(1), match.group(2)
    return code if code is not None else _SYMBOLS[symbol]


def _grouped(text: str, sep: str) -> bool:
    """Thousands-grouped number: first group 1-3 digits without a leading zero, then groups of 3."""
    return re.fullmatch(rf"[1-9][0-9]{{0,2}}(?:{re.escape(sep)}[0-9]{{3}})*", text) is not None


def _parse_number(text: str) -> Decimal | None:
    """Apply the separator rules to text made of ASCII digits, "," and "." only."""
    commas, dots = text.count(","), text.count(".")
    if commas == 0 and dots == 0:
        return Decimal(text)

    if commas and dots:
        decimal_sep = "," if text.rfind(",") > text.rfind(".") else "."
        thousands_sep = "." if decimal_sep == "," else ","
        if text.count(decimal_sep) != 1 or text.rfind(thousands_sep) > text.index(decimal_sep):
            return None
        whole, frac = text.split(decimal_sep)
        if not frac or not _grouped(whole, thousands_sep):
            return None
        return Decimal(f"{whole.replace(thousands_sep, '')}.{frac}")

    sep = "," if commas else "."
    if text.count(sep) > 1:
        # Repeated separator: thousands only, no decimal part.
        return Decimal(text.replace(sep, "")) if _grouped(text, sep) else None

    whole, frac = text.split(sep)
    if not whole or not frac:
        return None
    # Documented heuristic: "12,5" is a decimal and "1,234" is thousands. The
    # later budget step caps amounts, which bounds the cost of a wrong guess.
    if sep == "." or len(frac) <= 2:
        return Decimal(f"{whole}.{frac}")
    if len(frac) == 3 and _grouped(text, sep):
        return Decimal(whole + frac)
    return None


def canonicalize_amount(raw: str) -> CanonicalAmount:
    folded = unicodedata.normalize("NFKC", raw)
    text = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf").strip()

    leading = _LEADING_MARKER.match(text)
    trailing = _TRAILING_MARKER.search(text)
    if leading is not None and trailing is not None:
        return _INVALID  # a marker at both ends, or a marker with no number
    currency: str | None = None
    if leading is not None:
        currency = _marker_currency(leading)
        text = text[leading.end() :]
    elif trailing is not None:
        currency = _marker_currency(trailing)
        text = text[: trailing.start()]

    numeric = "".join(ch for ch in text if not unicodedata.category(ch).startswith("Z"))
    if len(numeric) > _MAX_NUMERIC_LEN or _NUMERIC_CHARS.fullmatch(numeric) is None:
        return _INVALID
    if not any(ch in "0123456789" for ch in numeric):
        return _INVALID

    value = _parse_number(numeric)
    if value is None:
        return _INVALID
    return CanonicalAmount(value=value, currency=currency, valid=True)


def to_cents(amount: CanonicalAmount) -> int | None:
    """Exact cents, or None if invalid or any digit past the second decimal is non-zero."""
    if not amount.valid or amount.value is None:
        return None
    sign, digits, exponent = amount.value.as_tuple()
    if sign != 0 or not isinstance(exponent, int):
        return None
    number = int("".join(map(str, digits)))
    if exponent >= -2:
        return number * 10 ** (exponent + 2)
    divisor = 10 ** (-exponent - 2)
    if number % divisor != 0:
        return None
    return number // divisor
