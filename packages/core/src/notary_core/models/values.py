"""Values as the Value Store hands them to the monitor."""

from typing import Literal

from notary_core.models.labels import NotaryModel, ValueRef

DecisionUnit = Literal["iban", "email", "url_host", "amount", "identifier"]
"""The unit in which a guarded value is compared: whole IBAN, whole address, whole host, ..."""


class ResolvedValue(NotaryModel):
    """A stored value with its text (a `ValueRef` only carries a hash; the monitor needs text)."""

    ref: ValueRef
    unit: DecisionUnit | None
    """None = free text (e.g. an email body), not a decision-unit value."""
    text: str
    """Raw, non-canonicalized text. `sha256(text.encode("utf-8")).hexdigest()` should equal
    `ref.content_hash`; a mismatch is a monitor BLOCK, so the model does not enforce it."""
