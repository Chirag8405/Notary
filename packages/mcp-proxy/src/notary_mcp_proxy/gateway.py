"""The Gateway: the only path from an agent to its tools.

It pins the session's tools, turns an agent's raw call into a labeled proposal, asks the monitor,
appends the decision to the audit chain BEFORE any effect, runs the tool through the injected
`ToolBackend` only on ALLOW, and labels the result. There is no network code: a real MCP transport
is P6, and a recording in-memory backend proves invariant I1 (no effect outside the adapter).

The object is deliberately mutable because it fronts I/O; every read property returns an
immutable snapshot, and the backend is private (no attribute or method hands it out).
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from notary_core.audit import append
from notary_core.gateway import GatewayLabeler, ValueStore
from notary_core.models import (
    AuditEntry,
    Decision,
    Event,
    IntentContract,
    Lane,
    LedgerEntry,
    NotaryModel,
    SessionState,
    Sha256Hex,
    ToolCallProposal,
)
from notary_core.monitor import Monitor
from notary_core.pinning import PinReport, compare_pins, pin_manifests
from notary_core.policy.sensitive_params import DEFAULT_POLICY, PolicyTable
from notary_core.resolver import ArgResolver
from notary_core.store import InMemoryValueStore
from notary_mcp_proxy.backend import ToolBackend

PREVIEW_LIMIT: int = 80
"""Characters kept in `ValueLabeled.preview`."""
HALT_AUDIT = "audit append failed"
ERR_EFFECT_NOT_LOGGED = "the effect ran but was not logged"
ERR_RESULT_NOT_LOGGED = "the effect ran but a result value was not logged"

AuditAppend = Callable[[Sequence[AuditEntry], Event], tuple[AuditEntry, ...]]
EventFactory = Callable[[str, Lane, int], Event]
"""Builds an event from `(run_id, lane, seq)`."""


class ToolPin(NotaryModel):
    """A tool pinned to the hash of its manifest (description and schema)."""

    tool: str
    manifest_hash: Sha256Hex


class RawCall(NotaryModel):
    """A call as the agent typed it: raw text per parameter."""

    call_id: str
    tool: str
    args: dict[str, str]


class MediationOutcome(NotaryModel):
    call_id: str
    status: Literal["blocked", "escalated", "executed", "tool_error", "halted"]
    decision: Decision | None
    endorsement_id: str | None
    error: str | None


@dataclass(frozen=True, slots=True)
class _Pending:
    """An escalated call waiting for the user. Replaced, never mutated, when it is resolved."""

    call: RawCall
    proposal: ToolCallProposal
    decision: Decision
    resolved: bool


class Gateway:
    def __init__(
        self,
        *,
        backend: ToolBackend,
        contract: IntentContract,
        ledger: Sequence[LedgerEntry],
        monitor: Monitor,
        labeler: GatewayLabeler,
        resolver: ArgResolver,
        run_id: str,
        lane: Lane = "notary",
        policy: PolicyTable = DEFAULT_POLICY,
        session: SessionState | None = None,
        store: ValueStore | None = None,
        audit_append: AuditAppend = append,
    ) -> None:
        self._backend = backend
        self._contract = contract
        self._ledger: tuple[LedgerEntry, ...] = tuple(ledger)
        self._monitor = monitor
        self._labeler = labeler
        self._resolver = resolver
        self._run_id = run_id
        self._lane: Lane = lane
        self._policy = policy
        self._session = session or SessionState(
            spent_cents=0, effects_used=0, egress_bytes_used=0, approvals_used=0
        )
        self._store: ValueStore = store if store is not None else InMemoryValueStore()
        self._audit_append = audit_append
        self._chain: tuple[AuditEntry, ...] = ()
        self._halted: str | None = None
        self._pins: dict[str, str] | None = None
        self._seen_calls: set[str] = set()
        self._escalations: dict[str, _Pending] = {}

    @property
    def chain(self) -> tuple[AuditEntry, ...]:
        return self._chain

    @property
    def store(self) -> ValueStore:
        return self._store

    @property
    def ledger(self) -> tuple[LedgerEntry, ...]:
        return self._ledger

    @property
    def session(self) -> SessionState:
        return self._session

    @property
    def halted(self) -> str | None:
        return self._halted

    def emit(self, make: EventFactory) -> bool:
        """Append one event; a failing append halts the gateway and leaves the chain unchanged.

        The runner uses this for `run_started`, `oracle_updated` and `run_finished`. It still
        tries to append after a halt (a `run_finished` is worth logging), but never retries.
        """
        event = make(self._run_id, self._lane, len(self._chain))
        try:
            self._chain = self._audit_append(self._chain, event)
        except Exception:
            self._halted = self._halted or HALT_AUDIT
            return False
        return True

    def pin_session(self) -> tuple[ToolPin, ...]:
        """Pin every tool the backend reports now; calling it again re-pins."""
        pins = pin_manifests(self._backend.list_tools())
        self._pins = pins
        return tuple(ToolPin(tool=tool, manifest_hash=digest) for tool, digest in pins.items())

    def check_drift(self) -> PinReport:
        """Compare the pins with what the backend reports now (drift is a rug pull, A10)."""
        if self._pins is None:
            raise ValueError("session is not pinned")
        return compare_pins(self._pins, self._backend.list_tools())

    def _halted_outcome(self, call_id: str, error: str | None = None) -> MediationOutcome:
        return MediationOutcome(
            call_id=call_id,
            status="halted",
            decision=None,
            endorsement_id=None,
            error=error or self._halted,
        )
