"""Pure text rendering for the CLI: models in, a string with a trailing newline out."""

from collections.abc import Sequence

from notary_cli.reports import AttackReport, GoalState
from notary_core.audit import GENESIS_HASH, VerifyResult
from notary_core.models import AuditEntry, Event, ExpectedOutcome
from notary_world.attacks import ALL_ATTACKS, ATTACK_NAMES, deciding_step
from notary_world.fuzz import FuzzReport

ATTACKER_WORDS: dict[GoalState, str] = {
    "reached": "attacker goal REACHED",
    "not_reached": "attacker goal not reached",
    "deferred": "attacker goal deferred",
}
USER_WORDS: dict[GoalState, str] = {
    "reached": "user goal achieved",
    "not_reached": "user goal not achieved",
    "deferred": "user goal deferred",
}
TABLE_HEADER = ("ID", "NAME", "VERDICT", "STEP", "RESULT")


def _outcome(outcome: ExpectedOutcome | None) -> str:
    """`verdict/check/code`, with `-` for anything missing."""
    if outcome is None:
        return "-"
    return f"{outcome.verdict}/{outcome.deciding_check or '-'}/{outcome.code or '-'}"


def render_attack_list() -> str:
    return "".join(
        f"{fixture.case.id}\t{ATTACK_NAMES[fixture.case.id]}\t"
        f"{fixture.case.expected.verdict}\t{deciding_step(fixture)}\n"
        for fixture in ALL_ATTACKS
    )


def render_attack_report(report: AttackReport) -> str:
    lines = [f"{report.attack_id} {report.name} (monitor={report.monitor})"]
    for check in report.checks:
        verdict = "OK" if check.matches else "MISMATCH"
        if check.known_deviation is not None:
            verdict += f" (known deviation: {check.known_deviation})"
        lines.append(
            f"  {check.call_id} {check.tool} expected {_outcome(check.expected)} "
            f"actual {_outcome(check.actual)} {verdict}"
        )
    lines.append(f"oracle: {ATTACKER_WORDS[report.attacker_goal]}; {USER_WORDS[report.user_goal]}")
    invariants = " ".join(
        f"{r.id}:{'ok' if r.passed else 'VIOLATED'}" for r in report.oracle.invariants
    )
    lines.append(f"invariants: {invariants}")
    lines.extend(f"  {r.detail}" for r in report.oracle.invariants if not r.passed)
    lines.append(f"result: {'OK' if report.ok else 'MISMATCH'}")
    return "\n".join(lines) + "\n"


def _result_cell(report: AttackReport) -> str:
    if not report.ok:
        return "MISMATCH"
    return "OK (deferred)" if report.deferred else "OK"


def render_attack_table(reports: Sequence[AttackReport]) -> str:
    rows = [
        (r.attack_id, r.name, r.expected_verdict, r.deciding_step, _result_cell(r)) for r in reports
    ]
    widths = [max(len(row[i]) for row in [TABLE_HEADER, *rows]) + 2 for i in range(4)]

    def line(row: tuple[str, str, str, str, str]) -> str:
        return "".join(cell.ljust(width) for cell, width in zip(row, widths, strict=False)) + row[4]

    attacks = sum(1 for r in reports if r.attack_id.startswith("A"))
    controls = sum(1 for r in reports if r.attack_id.startswith("B"))
    mismatches = sum(1 for r in reports if not r.ok)
    lines = [line(TABLE_HEADER), *(line(row) for row in rows)]
    lines.append(f"summary: {attacks} attacks, {controls} controls, {mismatches} mismatches")
    return "\n".join(lines) + "\n"


def render_fuzz_report(report: FuzzReport) -> str:
    lines = [
        f"fuzz: profile={report.profile} examples={report.examples} seed={report.seed}",
        f"violations: {len(report.violations)}",
    ]
    for violation in report.violations:
        lines.append(f"VIOLATION {violation.invariant_id}: {violation.detail}")
        lines.append(f"  minimized program ({len(violation.steps)} steps):")
        lines.extend(f"    {i}. {step}" for i, step in enumerate(violation.steps, start=1))
    lines.append(f"result: {'OK' if report.ok else 'VIOLATION'}")
    return "\n".join(lines) + "\n"


def render_replay(
    header: str | None,
    events: Sequence[Event],
    chain: Sequence[AuditEntry] | None,
    result: VerifyResult | None,
) -> str:
    lines: list[str] = [] if header is None else [header]
    lines.extend(f"[{e.seq:03d}] {e.type:<22} run={e.run_id}" for e in events)
    if chain is None or result is None:
        lines.append("chain: not present (plain event stream)")
    elif result.ok:
        head = chain[-1].hash if chain else GENESIS_HASH
        lines.append(f"chain: OK head={head} length={len(chain)}")
    else:
        lines.append(f"chain: FAILED {result.reason} at index {result.first_bad_index}")
    return "\n".join(lines) + "\n"
