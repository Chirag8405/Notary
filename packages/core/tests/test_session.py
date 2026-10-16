"""Pure helpers that advance the caller-owned session state."""

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from notary_core.models import SessionState
from notary_core.session import with_approval, with_effect


@pytest.mark.attack("A12")
def test_with_effect_adds_counts(make_session: Callable[..., SessionState]) -> None:
    before = make_session(spent_cents=100, effects_used=1, egress_bytes_used=10, approvals_used=2)
    after = with_effect(before, spent_cents=250, egress_bytes=40)
    assert after == make_session(
        spent_cents=350, effects_used=2, egress_bytes_used=50, approvals_used=2
    )
    assert before == make_session(
        spent_cents=100, effects_used=1, egress_bytes_used=10, approvals_used=2
    )


@pytest.mark.attack("A11")
def test_with_approval_increments(make_session: Callable[..., SessionState]) -> None:
    after = with_approval(make_session(spent_cents=5, approvals_used=1))
    assert after == make_session(spent_cents=5, approvals_used=2)


@pytest.mark.attack("A11")
def test_helpers_do_not_mutate(make_session: Callable[..., SessionState]) -> None:
    state = make_session(spent_cents=1, effects_used=1, egress_bytes_used=1, approvals_used=1)
    snapshot = state.model_dump_json()
    with_effect(state, spent_cents=5, egress_bytes=5)
    with_approval(state)
    assert state.model_dump_json() == snapshot
    with pytest.raises(ValidationError):
        state.spent_cents = 0
