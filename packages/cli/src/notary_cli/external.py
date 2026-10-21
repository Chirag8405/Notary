"""`notary attack --external`: run the external attack library and print its table.

The library (X1.., Y1.., `notary_world.external`) is separate from the CP1 contract: `attack --all`
still means A1-A14 and B1-B4. All computation is in `notary_world.external`; this module maps the
results to text and decides the exit code.
"""

from collections.abc import Sequence

from notary_core.models import ExpectedOutcome
from notary_world.external import ExternalAttack, ExternalResult

TABLE_HEADER = ("ID", "SERIES", "VECTOR", "FINAL CALL", "GOAL", "IF APPROVED", "RESULT")


def external_ok(attack: ExternalAttack, result: ExternalResult) -> bool:
    """Every call has its pinned outcome, I1-I6 hold, and the attacker goal is reached only in a
    declared residual."""
    return (
        result.matches
        and result.invariants_ok
        and (not result.goal_reached or attack.residual is not None)
    )


def _outcome(outcome: ExpectedOutcome | None) -> str:
    if outcome is None:
        return "-"
    return f"{outcome.verdict}/{outcome.deciding_check or '-'}/{outcome.code or '-'}"


def _row(attack: ExternalAttack, result: ExternalResult) -> tuple[str, ...]:
    last = result.checks[-1].actual
    declared = "" if attack.residual is None else f" ({attack.residual.kind})"
    return (
        attack.attack_id,
        attack.series,
        attack.vector,
        _outcome(last),
        ("REACHED" if result.goal_reached else "no") + declared,
        "reached" if result.goal_reached_if_approved else "no",
        "OK" if external_ok(attack, result) else "MISMATCH",
    )


def render_external_list(attacks: Sequence[ExternalAttack]) -> str:
    return "".join(
        f"{a.attack_id}\t{a.series}\t{a.vector}\t{a.scenario_id}\t{a.title}\n" for a in attacks
    )


def render_external_table(pairs: Sequence[tuple[ExternalAttack, ExternalResult]]) -> str:
    rows = [_row(attack, result) for attack, result in pairs]
    widths = [max(len(row[i]) for row in [TABLE_HEADER, *rows]) + 2 for i in range(6)]

    def line(row: tuple[str, ...]) -> str:
        return "".join(cell.ljust(width) for cell, width in zip(row, widths, strict=False)) + row[6]

    verdicts = [result.final_verdict for _, result in pairs]
    published = sum(1 for attack, _ in pairs if attack.series != "second_author")
    blind = [
        (result.prediction_verdict_matched is True, result.prediction_matched is True)
        for attack, result in pairs
        if attack.predicted is not None and not attack.informed
    ]
    lines = [line(TABLE_HEADER), *(line(row) for row in rows)]
    lines.append(
        f"summary: {len(pairs)} external attacks ({published} from published sets, "
        f"{len(pairs) - published} second-author); final call BLOCK {verdicts.count('BLOCK')}, "
        f"ESCALATE {verdicts.count('ESCALATE')}, ALLOW {verdicts.count('ALLOW')}; "
        f"attacker goal reached with escalations rejected {sum(r.goal_reached for _, r in pairs)}, "
        f"if every escalation is approved {sum(r.goal_reached_if_approved for _, r in pairs)}; "
        f"blind predictions: verdict right {sum(v for v, _ in blind)}/{len(blind)}, "
        f"verdict+check+code right {sum(e for _, e in blind)}/{len(blind)}; "
        f"mismatches {sum(1 for a, r in pairs if not external_ok(a, r))}"
    )
    return "\n".join(lines) + "\n"


def render_external_report(attack: ExternalAttack, result: ExternalResult) -> str:
    lines = [
        f"{attack.attack_id} {attack.title}",
        f"  source: {attack.provenance.source} ({attack.provenance.licence}; "
        f"{attack.provenance.wording}; retrieved {attack.provenance.retrieved})",
        f"  vector: {attack.vector}; scenario: {attack.scenario_id}; goal: {attack.goal}",
    ]
    for check in result.checks:
        verdict = "OK" if check.matches else "MISMATCH"
        lines.append(
            f"  {check.call_id} expected {_outcome(check.expected)} "
            f"actual {_outcome(check.actual)} {verdict}"
        )
    if attack.predicted is not None:
        lines.append(f"  predicted (before the first run): {_outcome(attack.predicted)}")
    lines.append(
        f"oracle: attacker goal {'REACHED' if result.goal_reached else 'not reached'}; "
        f"if every escalation is approved: "
        f"{'reached' if result.goal_reached_if_approved else 'not reached'}; "
        f"invariants {'ok' if result.invariants_ok else 'VIOLATED'}"
    )
    if attack.residual is not None:
        issue = "" if attack.residual.issue is None else f" #{attack.residual.issue}"
        lines.append(f"residual: {attack.residual.kind}{issue}: {attack.residual.reason}")
    lines.append(f"result: {'OK' if external_ok(attack, result) else 'MISMATCH'}")
    return "\n".join(lines) + "\n"
