"""Pure helpers that advance the caller-owned `SessionState`. Core never stores session state."""

from notary_core.models import SessionState


def with_effect(session: SessionState, *, spent_cents: int, egress_bytes: int) -> SessionState:
    """A new state after an effect executed: one more effect, plus its spend and egress."""
    return SessionState(
        spent_cents=session.spent_cents + spent_cents,
        effects_used=session.effects_used + 1,
        egress_bytes_used=session.egress_bytes_used + egress_bytes,
        approvals_used=session.approvals_used,
    )


def with_approval(session: SessionState) -> SessionState:
    """A new state after the user granted an approval."""
    return SessionState(
        spent_cents=session.spent_cents,
        effects_used=session.effects_used,
        egress_bytes_used=session.egress_bytes_used,
        approvals_used=session.approvals_used + 1,
    )
