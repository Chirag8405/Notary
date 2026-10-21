"""Test doubles and builders for the gateway tests (no other package is used)."""

from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType

from notary_core.audit import append
from notary_core.canon import sha256_hex
from notary_core.gateway import (
    LabelingPolicy,
    ToolOriginRule,
    ToolResultField,
    make_labeler,
)
from notary_core.models import (
    AuditEntry,
    Decision,
    DecisionUnit,
    EffectBudget,
    EmailOrigin,
    EndorseMarker,
    Event,
    FileOrigin,
    FreeMarker,
    IntentContract,
    Label,
    LedgerEntry,
    LedgerMarker,
    LlmOrigin,
    Marker,
    ResolvedValue,
    SessionState,
    ToolCallProposal,
    ToolEffect,
    ToolScope,
    UserAuthoredSource,
    UserEndorsedSource,
    UserOrigin,
    ValueRef,
)
from notary_core.monitor import Monitor, decide
from notary_core.pinning import ToolManifest, manifest_hash
from notary_core.policy.sensitive_params import (
    DEFAULT_POLICY,
    ParamPolicy,
    PolicyTable,
    make_tool_policy,
)
from notary_core.resolver import ArgResolver, ArgumentResolver
from notary_mcp_proxy import (
    BackendEffect,
    BackendRecord,
    BackendResult,
    Gateway,
    schema_text,
)

ACME_IBAN = "DE00ACME00000000000001"
ATTACKER_IBAN = "DE00ATTACKER0000000001"
ACCOUNTANT_EMAIL = "accountant@acme.example"
SECRET = "CODE-8841"
SECRET_PATH = "secrets/2fa.txt"
BODY = f"Amount due: 120.00 EUR. Pay to IBAN {ACME_IBAN}."

AuditAppend = Callable[[Sequence[AuditEntry], Event], tuple[AuditEntry, ...]]


def default_manifests() -> list[ToolManifest]:
    empty = schema_text({"type": "object", "properties": {}})
    return [
        ToolManifest(name="read_inbox", description="List the emails.", input_schema=empty),
        ToolManifest(
            name="read_file",
            description="Read a file by path.",
            input_schema=schema_text({"type": "object", "required": ["path"]}),
        ),
        ToolManifest(
            name="pay_bill",
            description="Pay a bill to a payee by IBAN.",
            input_schema=schema_text({"type": "object", "required": ["payee", "amount"]}),
        ),
        ToolManifest(name="send_email", description="Send an email.", input_schema=empty),
        ToolManifest(name="add_contact", description="Add a contact.", input_schema=empty),
    ]


def _read(summary: str) -> BackendEffect:
    return BackendEffect(summary=summary, spent_cents=0, egress_bytes=0, mutating=False)


def inbox_result(body: str = BODY) -> BackendResult:
    record = BackendRecord(
        record_id="m-dec",
        readers=("*",),
        fields=(
            ToolResultField(name="sender", text="billing@acme-utilities.example", unit=None),
            ToolResultField(name="body", text=body, unit=None),
        ),
    )
    return BackendResult(records=(record,), effect=_read("read 1 messages"), error=None)


def default_results() -> dict[str, BackendResult]:
    secret = BackendRecord(
        record_id=SECRET_PATH,
        readers=("user",),
        fields=(ToolResultField(name="text", text=SECRET, unit=None),),
    )
    write = BackendEffect(summary="paid", spent_cents=12000, egress_bytes=0, mutating=True)
    mail = BackendEffect(summary="sent email", spent_cents=0, egress_bytes=20, mutating=True)
    contact = BackendEffect(summary="added contact", spent_cents=0, egress_bytes=0, mutating=True)
    return {
        "read_inbox": inbox_result(),
        "read_file": BackendResult(records=(secret,), effect=_read("read file"), error=None),
        "pay_bill": BackendResult(records=(), effect=write, error=None),
        "send_email": BackendResult(records=(), effect=mail, error=None),
        "add_contact": BackendResult(records=(), effect=contact, error=None),
    }


class RecordingBackend:
    """A ToolBackend that logs every `call_tool` and can be rug-pulled or made to fail."""

    def __init__(
        self,
        manifests: Sequence[ToolManifest] | None = None,
        results: Mapping[str, BackendResult] | None = None,
        raises: Mapping[str, Exception] | None = None,
    ) -> None:
        start = default_manifests() if manifests is None else manifests
        self.manifests: list[ToolManifest] = list(start)
        self.results: dict[str, BackendResult] = {**default_results(), **(results or {})}
        self.raises: dict[str, Exception] = dict(raises or {})
        self.calls: list[tuple[str, dict[str, str]]] = []
        self.probe: Callable[[], tuple[AuditEntry, ...]] | None = None
        self.probed: list[tuple[AuditEntry, ...]] = []

    def list_tools(self) -> Sequence[ToolManifest]:
        return tuple(self.manifests)

    def call_tool(self, tool: str, args: Mapping[str, str]) -> BackendResult:
        if self.probe is not None:
            self.probed.append(self.probe())
        self.calls.append((tool, dict(args)))
        if tool in self.raises:
            raise self.raises[tool]
        return self.results.get(tool, BackendResult(records=(), effect=None, error=None))

    def rug_pull(self, tool: str, addition: str) -> None:
        """The server rewrites a tool's description after the session started."""
        self.manifests = [
            m.model_copy(update={"description": m.description + addition}) if m.name == tool else m
            for m in self.manifests
        ]


_FREE = FreeMarker(kind="free")
_SCOPES: dict[str, tuple[dict[str, Marker], ToolEffect]] = {
    "read_inbox": ({}, "read"),
    "read_file": ({"path": _FREE}, "read"),
    "pay_bill": (
        {"payee": LedgerMarker(kind="ledger", ledger="payees"), "amount": _FREE},
        "irreversible",
    ),
    "send_email": (
        {"to": LedgerMarker(kind="ledger", ledger="contacts"), "subject": _FREE, "body": _FREE},
        "write",
    ),
    "add_contact": ({"name": EndorseMarker(kind="endorse")}, "write"),
}


def make_contract(backend: RecordingBackend, *, max_approvals: int = 3) -> IntentContract:
    """A contract whose scopes pin the backend's CURRENT manifest hashes."""
    scopes = tuple(
        ToolScope(
            tool=m.name,
            params=_SCOPES[m.name][0],
            manifest_hash=manifest_hash(m),
            effect=_SCOPES[m.name][1],
        )
        for m in backend.list_tools()
        if m.name in _SCOPES
    )
    return IntentContract(
        contract_id="contract-test",
        user_intent="test",
        allowed_tools=scopes,
        budget=EffectBudget(
            max_effects=10,
            max_spend_cents=20000,
            max_egress_bytes=10000,
            max_call_amount_cents=20000,
            max_approvals=max_approvals,
        ),
        egress_hosts=(),
        authorized_irreversible=("pay_bill",),
    )


def make_policy() -> PolicyTable:
    """`DEFAULT_POLICY` plus read-only rows for the read tools, as the world's policy does."""
    free_identifier = ParamPolicy(unit="identifier", floor=_FREE, kind="identifier")
    rows = {
        **DEFAULT_POLICY,
        "read_inbox": make_tool_policy("read", {}),
        "read_file": make_tool_policy("read", {"path": free_identifier}),
    }
    return MappingProxyType(rows)


def real_monitor(policy: PolicyTable) -> Monitor:
    def monitor(
        contract: IntentContract,
        proposal: ToolCallProposal,
        values: Mapping[str, ResolvedValue],
        ledger: Sequence[LedgerEntry],
        session: SessionState,
    ) -> Decision:
        return decide(contract, proposal, values, ledger, session, policy=policy)

    return monitor


def make_label_fn() -> Callable[..., tuple[ResolvedValue, ...]]:
    policy = LabelingPolicy(
        origins=(
            ToolOriginRule(tool="read_inbox", origin=EmailOrigin(kind="email")),
            ToolOriginRule(tool="read_file", origin=FileOrigin(kind="file")),
        ),
        stamps=(),
    )
    return make_labeler(policy)


def user_entry(
    entry_id: str, ledger: str, key: str, unit: DecisionUnit, canonical: str
) -> LedgerEntry:
    label = Label(
        origin=UserOrigin(kind="user"), integrity="trusted", readers=("*",), span_pointer=None
    )
    ref = ValueRef(id=f"ledger.{entry_id}", label=label, content_hash=sha256_hex(canonical))
    return LedgerEntry(
        entry_id=entry_id,
        ledger=ledger,
        key=key,
        value=ref,
        unit=unit,
        canonical=canonical,
        source=UserAuthoredSource(kind="user_authored"),
    )


def default_ledger() -> tuple[LedgerEntry, ...]:
    return (
        user_entry("payee-acme", "payees", "Acme Utilities", "iban", ACME_IBAN),
        user_entry("contact-accountant", "contacts", "Sam", "email", ACCOUNTANT_EMAIL),
    )


def endorsed_entry(
    ref: ValueRef, *, endorsement_id: str = "e1", canonical: str = "alpha consulting"
) -> LedgerEntry:
    """The ledger entry for an approved `add_contact` name, as the server builds it."""
    return LedgerEntry(
        entry_id=f"led-{endorsement_id}-name",
        ledger="endorsed",
        key=f"name: {canonical}",
        value=ref,
        unit="identifier",
        canonical=canonical,
        source=UserEndorsedSource(kind="user_endorsed", endorsement_id=endorsement_id),
    )


def plain_value(value_id: str, text: str) -> ResolvedValue:
    label = Label(
        origin=LlmOrigin(kind="llm", context_readers=("*",)),
        integrity="untrusted",
        readers=("*",),
        span_pointer=None,
    )
    ref = ValueRef(id=value_id, label=label, content_hash=sha256_hex(text))
    return ResolvedValue(ref=ref, unit=None, text=text)


def make_gateway(
    backend: RecordingBackend,
    *,
    contract: IntentContract | None = None,
    ledger: Sequence[LedgerEntry] | None = None,
    resolver: ArgResolver | None = None,
    max_approvals: int = 3,
    session: SessionState | None = None,
    audit_append: AuditAppend = append,
) -> Gateway:
    policy = make_policy()
    return Gateway(
        backend=backend,
        contract=contract or make_contract(backend, max_approvals=max_approvals),
        ledger=default_ledger() if ledger is None else ledger,
        monitor=real_monitor(policy),
        labeler=make_label_fn(),
        resolver=resolver or ArgumentResolver(),
        run_id="run-test",
        policy=policy,
        session=session,
        audit_append=audit_append,
    )
