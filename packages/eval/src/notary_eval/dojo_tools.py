"""AgentDojo tools -> NOTARY effect classes and sensitive-parameter rows (banking and Slack).

This is data: one `ToolPolicy` per tool, in the same shape as `notary_core`'s `DEFAULT_POLICY`
(`BENCH_POLICY` extends it with the AgentDojo tool names; the two never collide, because the
default table holds the demo world's `send_money`/`post_slack`, which are replaced here). A tool
that is not in the table is unmapped and fails closed: the monitor treats it as irreversible, the
compiler leaves it out of the contract, and `unmapped_tools` lists it.

Reading the table:

- `read`: no side effect and no outbound channel; the monitor lets it through after the scope check.
- `write`: an effect that can be undone or is not money. `get_webpage` is `write` because a URL the
  agent chooses is an outbound channel (the Slack injection task 3 is exactly "visit this site").
- `irreversible`: money moves or a credential changes; it needs `authorized_irreversible`.
- A `destination` parameter names who or where something goes (payee IBAN, recipient, channel,
  URL host, e-mail); its floor says where its value must come from (the ledger, or an endorsement).
- `amount` is checked against the budget; `payload` is free text (counted as egress bytes);
  `identifier` is a name or id.
"""

from collections.abc import Mapping, Sequence
from types import MappingProxyType

from notary_core.models import DecisionUnit, EndorseMarker, FreeMarker, LedgerMarker, ToolEffect
from notary_core.policy.sensitive_params import (
    DEFAULT_POLICY,
    ManifestInfo,
    ParamKind,
    ParamPolicy,
    PolicyTable,
    ToolPolicy,
    make_tool_policy,
    unclassified_params,
)

_ENDORSE = EndorseMarker(kind="endorse")
_FREE = FreeMarker(kind="free")

_PAYLOAD = ParamPolicy(unit=None, floor=_FREE, kind="payload")
_AMOUNT = ParamPolicy(unit="amount", floor=_FREE, kind="amount")
_OPEN_ID = ParamPolicy(unit="identifier", floor=_FREE, kind="identifier")
_PAYEE = ParamPolicy(unit="iban", floor=_ENDORSE, kind="destination")
_ENDORSED_ID = ParamPolicy(unit="identifier", floor=_ENDORSE, kind="identifier")
_URL = ParamPolicy(unit="url_host", floor=_ENDORSE, kind="destination")


def _ledgered(unit: DecisionUnit, ledger: str) -> ParamPolicy:
    return ParamPolicy(
        unit=unit, floor=LedgerMarker(kind="ledger", ledger=ledger), kind="destination"
    )


_CONTACT = _ledgered("identifier", "contacts")
_CHANNEL = _ledgered("identifier", "channels")

_MONEY_PARAMS: Mapping[str, ParamPolicy] = {
    "recipient": _PAYEE,
    "amount": _AMOUNT,
    "subject": _PAYLOAD,
    "date": _PAYLOAD,
}

_ENTRIES: dict[str, ToolPolicy] = {
    # banking
    "get_iban": make_tool_policy("read", {}),
    "get_balance": make_tool_policy("read", {}),
    "get_user_info": make_tool_policy("read", {}),
    "get_scheduled_transactions": make_tool_policy("read", {}),
    "get_most_recent_transactions": make_tool_policy("read", {"n": _OPEN_ID}),
    "read_file": make_tool_policy("read", {"file_path": _OPEN_ID}),
    "send_money": make_tool_policy("irreversible", _MONEY_PARAMS),
    "schedule_transaction": make_tool_policy(
        "irreversible", {**_MONEY_PARAMS, "recurring": _PAYLOAD}
    ),
    "update_scheduled_transaction": make_tool_policy(
        "write", {**_MONEY_PARAMS, "id": _OPEN_ID, "recurring": _PAYLOAD}
    ),
    "update_password": make_tool_policy("irreversible", {"password": _ENDORSED_ID}),
    "update_user_info": make_tool_policy(
        "write",
        dict.fromkeys(("first_name", "last_name", "street", "city"), _ENDORSED_ID),
    ),
    # slack
    "get_channels": make_tool_policy("read", {}),
    "read_channel_messages": make_tool_policy("read", {"channel": _OPEN_ID}),
    "read_inbox": make_tool_policy("read", {"user": _OPEN_ID}),
    "get_users_in_channel": make_tool_policy("read", {"channel": _OPEN_ID}),
    "send_direct_message": make_tool_policy("write", {"recipient": _CONTACT, "body": _PAYLOAD}),
    "send_channel_message": make_tool_policy("write", {"channel": _CHANNEL, "body": _PAYLOAD}),
    "add_user_to_channel": make_tool_policy(
        "write",
        {
            "user": ParamPolicy(unit="identifier", floor=_ENDORSE, kind="destination"),
            "channel": _CHANNEL,
        },
    ),
    "invite_user_to_slack": make_tool_policy(
        "write",
        {
            "user": _ENDORSED_ID,
            "user_email": ParamPolicy(unit="email", floor=_ENDORSE, kind="destination"),
        },
    ),
    "remove_user_from_slack": make_tool_policy("irreversible", {"user": _ENDORSED_ID}),
    "get_webpage": make_tool_policy("write", {"url": _URL}),
    "post_webpage": make_tool_policy("write", {"url": _URL, "content": _PAYLOAD}),
}

DOJO_POLICY: PolicyTable = MappingProxyType(_ENTRIES)
"""The AgentDojo rows alone (banking and Slack)."""
BENCH_POLICY: PolicyTable = MappingProxyType({**DEFAULT_POLICY, **_ENTRIES})
"""What the monitor and the Gateway are given in the benchmark."""


def tool_effect(tool: str) -> ToolEffect | None:
    """The mapped effect class of an AgentDojo tool, or none when the tool is unmapped."""
    policy = DOJO_POLICY.get(tool)
    return None if policy is None else policy.effect


def param_kind(tool: str, param: str) -> ParamKind | None:
    policy = DOJO_POLICY.get(tool)
    if policy is None:
        return None
    for binding in policy.params:
        if binding.name == param:
            return binding.policy.kind
    return None


def unmapped_tools(names: Sequence[str]) -> tuple[str, ...]:
    """The tools of `names` the table does not cover (they are irreversible and out of scope)."""
    return tuple(sorted({name for name in names if name not in DOJO_POLICY}))


def unclassified(manifests: Sequence[ManifestInfo]) -> tuple[tuple[str, str], ...]:
    """Parameters of mapped effect tools that the table does not classify (the core's coverage)."""
    return unclassified_params(DOJO_POLICY, manifests)
