"""Intent contract: what the user authorised, fixed before the agent runs."""

from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from notary_core.models.labels import NotaryModel, Sha256Hex


class LiteralMarker(NotaryModel):
    """Parameter must equal this exact value."""

    kind: Literal["literal"]
    value: str | int | bool


class NamedSourceMarker(NotaryModel):
    """Parameter must come from a named source (e.g. a contact book entry)."""

    kind: Literal["named_source"]
    source: str


class LedgerMarker(NotaryModel):
    """Parameter must resolve to an entry of the named ledger."""

    kind: Literal["ledger"]
    ledger: str


class EndorseMarker(NotaryModel):
    """Parameter may be untrusted but only after explicit human endorsement."""

    kind: Literal["endorse"]


class FreeMarker(NotaryModel):
    """Parameter is unconstrained by the contract."""

    kind: Literal["free"]


Marker = Annotated[
    LiteralMarker | NamedSourceMarker | LedgerMarker | EndorseMarker | FreeMarker,
    Field(discriminator="kind"),
]


ToolEffect = Literal["read", "write", "irreversible"]
"""`read` = no side effect AND no outbound channel.

A tool that can reach an external host is `write`.
"""


class EffectBudget(NotaryModel):
    max_effects: Annotated[int, Field(ge=0)]
    """Counts non-read calls (sends)."""
    max_spend_cents: Annotated[int, Field(ge=0)]
    """Cumulative spend cap (single currency, cents)."""
    max_egress_bytes: Annotated[int, Field(ge=0)]
    max_call_amount_cents: Annotated[int, Field(ge=0)]
    """Per-call amount cap."""
    max_approvals: Annotated[int, Field(ge=0)]
    """Endorsement approvals per session; past it an ESCALATE becomes a BLOCK."""


class ToolScope(NotaryModel):
    tool: str
    params: dict[str, Marker]
    manifest_hash: Sha256Hex
    """sha256 of the tool description + schema, pinned at session start."""
    effect: ToolEffect


class IntentContract(NotaryModel):
    contract_id: str
    user_intent: str
    allowed_tools: tuple[ToolScope, ...]
    budget: EffectBudget
    egress_hosts: tuple[str, ...]
    """Allowlisted registrable domains for outgoing URLs: lowercase, no scheme, no path."""
    authorized_irreversible: tuple[str, ...]
    """Tool names the user explicitly authorized; each must be an `irreversible` tool in scope."""

    @field_validator("egress_hosts")
    @classmethod
    def _egress_hosts_are_bare_lowercase_domains(cls, hosts: tuple[str, ...]) -> tuple[str, ...]:
        for host in hosts:
            if host != host.lower() or not host or any(c in host for c in "/: \t\n@"):
                raise ValueError(f"egress host must be a bare lowercase domain: {host!r}")
        return hosts

    @model_validator(mode="after")
    def _tools_are_consistent(self) -> Self:
        names = [scope.tool for scope in self.allowed_tools]
        if len(names) != len(set(names)):
            raise ValueError("duplicate tool names in allowed_tools")
        irreversible = {s.tool for s in self.allowed_tools if s.effect == "irreversible"}
        for tool in self.authorized_irreversible:
            if tool not in irreversible:
                raise ValueError(
                    f"authorized_irreversible tool is not an irreversible tool in scope: {tool!r}"
                )
        return self
