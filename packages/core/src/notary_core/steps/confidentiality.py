"""Step 5: data may only flow to principals that may read it, and outgoing URLs must be allowed."""

from notary_core.endorsement import ENDORSED_LEDGER
from notary_core.ledger import find_exact
from notary_core.models import DiffCard, DiffRow, LlmOrigin, ResolvedValue
from notary_core.models.decision import ReasonCode, StepOutcome
from notary_core.pipeline import StepInput
from notary_core.policy.sensitive_params import param_policy
from notary_core.provenance import join_all_readers, readers_allow
from notary_core.units import canonicalize, registrable_domain
from notary_core.urls import extract_urls


def _block(code: ReasonCode, detail: str) -> StepOutcome:
    return StepOutcome(verdict="BLOCK", code=code, detail=detail, diff_card=None)


def check_confidentiality(inp: StepInput) -> StepOutcome | None:
    """BLOCK when data would reach a non-reader, or an untrusted body names an unlisted host.
    ESCALATE when text the model wrote after a private read goes to a non-reader of that read.

    Rule 1 (readers): the join of the readers of every data argument (anything that is neither a
    destination nor an amount) must include each destination principal. Rule 2 (egress): every URL
    in an untrusted data argument must have its host or registrable domain on the contract's
    allowlist. Rule 3 (context): a data argument the model wrote itself carries the readers of
    everything the model had read (`LlmOrigin.context_readers`); under the attacker model the
    model may re-type a secret in any form, which rule 1 cannot see. A destination outside those
    readers ESCALATEs with a card showing the text, unless the user already endorsed exactly that
    text. Rule 1 runs first, then rule 2, then rule 3. Details are constant strings (A12).
    """
    data: list[tuple[str, ResolvedValue]] = []
    destinations: list[str] = []
    for name, ref in inp.proposal.args.items():
        value = inp.values.get(ref.id)
        if value is None:
            return _block("CONF_READER_VIOLATION", "data may not flow to this destination")
        policy = param_policy(inp.policy, inp.proposal.tool, name)
        if policy.kind == "destination":
            principal = canonicalize(policy.unit or "identifier", value.text).value
            destinations.append(principal)
        elif policy.kind != "amount":
            data.append((name, value))

    readers = join_all_readers(value.ref.label.readers for _, value in data)
    if not all(readers_allow(readers, principal) for principal in destinations):
        return _block("CONF_READER_VIOLATION", "data may not flow to this destination")

    allowed = set(inp.contract.egress_hosts)
    for _, value in data:
        if value.ref.label.integrity != "untrusted":
            continue
        for url in extract_urls(value.text):
            if url.host not in allowed and registrable_domain(url.host) not in allowed:
                return _block("CONF_URL_NOT_ALLOWED", "URL host is not allowed")

    rows: list[DiffRow] = []
    for name, value in sorted(data, key=lambda item: item[0]):
        origin = value.ref.label.origin
        if not isinstance(origin, LlmOrigin):
            continue
        if all(readers_allow(origin.context_readers, principal) for principal in destinations):
            continue
        unit = param_policy(inp.policy, inp.proposal.tool, name).unit or "identifier"
        text = canonicalize(unit, value.text).value
        if find_exact(inp.ledger, unit, text, ENDORSED_LEDGER) is not None:
            continue
        rows.append(
            DiffRow(
                param=name,
                value_id=value.ref.id,
                origin=origin,
                integrity=value.ref.label.integrity,
                preview=text,
                nearest_ledger_value=None,
                differing_positions=(),
            )
        )
    if rows:
        return StepOutcome(
            verdict="ESCALATE",
            code="CONF_CONTEXT_ESCALATE",
            detail="written after reading data this destination may not see",
            diff_card=DiffCard(rows=tuple(rows)),
        )
    return None
