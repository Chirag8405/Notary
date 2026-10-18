"""`notary` CLI: fuzz | replay | bench | attack.

The CLI only parses options, calls `notary_world`/`notary_core`, prints and sets exit codes.
Exit codes: 0 success (everything matches, zero violations, chain verified); 1 a verification
failed (outcome mismatch, fuzz violation, broken or truncated audit chain); 2 usage error,
unreadable or invalid input, or an unimplemented command. `--save-dir` is the only place it writes.
"""

import json
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NamedTuple, NoReturn

import typer
from pydantic import Field, JsonValue, TypeAdapter, ValidationError

from notary_cli.render import (
    render_attack_list,
    render_attack_report,
    render_attack_table,
    render_fuzz_report,
    render_replay,
)
from notary_cli.reports import AttackReport, MonitorChoice, build_report
from notary_core.audit import GENESIS_HASH, VerifyResult, verify_chain_detailed
from notary_core.models import AuditEntry, Event, NotaryModel, Sha256Hex
from notary_eval import DEFENCES, export_results, run_library
from notary_world.attacks import ALL_ATTACKS, ALL_CONTROLS, AttackNotFoundError
from notary_world.executor import RunRecord
from notary_world.fuzz import FuzzProfile, run_fuzz

app = typer.Typer(no_args_is_help=True, add_completion=False, help="NOTARY command line.")
_EVENT: TypeAdapter[Event] = TypeAdapter(Event)
_EVENTS: TypeAdapter[list[Event]] = TypeAdapter(list[Event])
_ENTRY: TypeAdapter[AuditEntry] = TypeAdapter(AuditEntry)
_OBJECT: TypeAdapter[dict[str, JsonValue]] = TypeAdapter(dict[str, JsonValue])

EXIT_CODES = (
    "Exit codes: 0 success (all outcomes match, zero violations, chain verified); "
    "1 verification failed (outcome mismatch, fuzz violation, broken or truncated chain); "
    "2 usage error, invalid input or not implemented."
)


class MonitorOption(StrEnum):
    real = "real"
    fake = "fake"


class ProfileOption(StrEnum):
    ci = "ci"
    full = "full"


def read_events(path: Path) -> list[Event]:
    """Parse a JSON file holding one event, a JSON array of events, or JSON lines."""
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("["):
        return _EVENTS.validate_json(text)
    try:
        return [_EVENT.validate_json(text)]
    except ValueError:
        return [_EVENT.validate_json(line) for line in text.splitlines() if line.strip()]


def _usage_error(message: str) -> NoReturn:
    typer.echo(message, err=True)
    raise typer.Exit(code=2)


def _reason(error: Exception) -> str:
    """First line of an error, which never holds a path."""
    return str(error).splitlines()[0] if str(error) else type(error).__name__


class Loaded(NamedTuple):
    """What `replay` read: the events, and the audit chain when the file has one."""

    header: str | None
    events: list[Event]
    chain: list[AuditEntry] | None
    unreadable: int | None = None
    """Index of the first chain line that is not an `AuditEntry` (a partial or damaged line)."""


def _is_chain_text(text: str) -> bool:
    """Whether the first line is a JSON object shaped like an `AuditEntry` (one entry per line)."""
    first = next((line for line in text.splitlines() if line.strip()), "")
    try:
        data = _OBJECT.validate_json(first)
    except ValueError:
        return False
    return {"index", "prev_hash", "hash", "event"} <= data.keys()


def _load_chain(text: str) -> Loaded:
    chain: list[AuditEntry] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            chain.append(_ENTRY.validate_json(line))
        except ValueError:
            events = [entry.event for entry in chain]
            return Loaded(_chain_header(chain), events, chain, unreadable=len(chain))
    return Loaded(_chain_header(chain), [entry.event for entry in chain], chain)


def _chain_header(chain: Sequence[AuditEntry]) -> str | None:
    if not chain:
        return None
    first = chain[0].event
    return f"run {first.run_id} lane={first.lane} events={len(chain)}"


def _load_run_or_events(path: Path) -> Loaded:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        _usage_error(f"not a run record or event file: {type(error).__name__}")
    try:
        record = RunRecord.model_validate_json(text)
    except ValidationError:
        pass
    else:
        header = f"run {record.run_id} lane={record.lane} events={len(record.chain)}"
        return Loaded(header, list(record.events), list(record.chain))
    if _is_chain_text(text):
        return _load_chain(text)
    try:
        return Loaded(None, read_events(path), None)
    except ValueError as error:
        _usage_error(f"not a run record or event file: {_reason(error)}")


class AnchorFile(NotaryModel):
    """The shape the proxy writes beside its chain (`<run>.anchor.json`)."""

    run_id: str
    length: Annotated[int, Field(ge=0)]
    head: Sha256Hex | None
    """The hash of the last entry; null for an empty chain."""


def _read_anchor(path: Path) -> tuple[int, str]:
    """`(length, head)` from an anchor file (a null `head` is the empty chain)."""
    try:
        anchor = AnchorFile.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        _usage_error(f"not an anchor file: {_reason(error)}")
    return anchor.length, GENESIS_HASH if anchor.head is None else anchor.head


@app.command()
def replay(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    anchor: Annotated[
        Path | None,
        typer.Option(
            "--anchor", dir_okay=False, help="Anchor file (JSON with length and head) of the run."
        ),
    ] = None,
    expect_head: Annotated[
        str | None, typer.Option("--expect-head", help="Head hash recorded outside the log.")
    ] = None,
    expect_length: Annotated[
        int | None, typer.Option("--expect-length", help="Chain length recorded outside the log.")
    ] = None,
) -> None:
    """Print the events in FILE; for a saved run or a proxy chain also verify its audit chain.

    FILE is a run record written by `attack --save-dir`, a proxy chain (`<run>.chain.jsonl`, one
    audit entry per line), or a plain event file (a JSON array, one event, or JSON lines). The
    anchors (`--anchor FILE` or `--expect-head` and `--expect-length`) detect tail truncation,
    which the chain alone cannot.

    Exit codes: 0 chain verified (or plain event file); 1 chain broken, unreadable line or anchor
    mismatch; 2 invalid input or anchors given for a file without a chain.
    """
    if anchor is not None and (expect_head is not None or expect_length is not None):
        _usage_error("give --anchor or --expect-head/--expect-length, not both")
    loaded = _load_run_or_events(file)
    if anchor is not None:
        expect_length, expect_head = _read_anchor(anchor)
    if loaded.chain is None:
        if anchor is not None or expect_head is not None or expect_length is not None:
            flags = "--anchor" if anchor is not None else "--expect-head/--expect-length"
            _usage_error(f"{flags} need a run file with an audit chain")
        typer.echo(render_replay(None, loaded.events, None, None), nl=False)
        return
    if loaded.unreadable is not None:
        result = VerifyResult(
            ok=False, first_bad_index=loaded.unreadable, reason="unreadable entry"
        )
    else:
        result = verify_chain_detailed(
            loaded.chain, expected_length=expect_length, expected_head=expect_head
        )
    typer.echo(render_replay(loaded.header, loaded.events, loaded.chain, result), nl=False)
    if not result.ok:
        raise typer.Exit(code=1)


@app.command()
def bench(
    out: Annotated[
        Path | None, typer.Option("--out", help="Write <defence>.json results here (a directory).")
    ] = None,
    seed: Annotated[int, typer.Option("--seed", min=0, help="Reproducible seed.")] = 0,
) -> None:
    """Run the attack library (A1-A14, B1-B4) with no defence and with the real monitor.

    Prints attacks that succeeded and controls whose user goal was met per lane. `--out` writes
    one results file per lane for the chart tooling.

    Exit codes: 0 success; 1 the NOTARY lane let an attack succeed or broke a benign control.
    """
    failed = False
    for defence in DEFENCES:
        results = run_library(defence, seed=seed)
        attacks = [r for r in results.results if r.task_id.startswith("A")]
        controls = [r for r in results.results if r.task_id.startswith("B")]
        hit = sum(r.attack_succeeded for r in attacks)
        kept = sum(r.utility for r in controls)
        typer.echo(
            f"{defence:<7} attacks succeeded {hit}/{len(attacks)}  "
            f"controls completed {kept}/{len(controls)}"
        )
        if defence == "notary" and (hit or kept != len(controls)):
            failed = True
        if out is not None:
            out.mkdir(parents=True, exist_ok=True)
            export_results(results, out / f"{defence}.json")
    if failed:
        raise typer.Exit(code=1)


@app.command()
def fuzz(
    examples: Annotated[int, typer.Option("--examples", min=1, help="Programs to try.")] = 100,
    seed: Annotated[int, typer.Option("--seed", min=0, help="Reproducible seed.")] = 0,
    profile: Annotated[
        ProfileOption, typer.Option("--profile", help="ci is small, full explores deeper.")
    ] = ProfileOption.ci,
) -> None:
    """Fuzz the real monitor with an adversarial LLM and check invariants I1-I6 after every step.

    Exit codes: 0 zero violations; 1 a violation (the minimized program is printed);
    2 usage error.
    """
    chosen: FuzzProfile = "full" if profile is ProfileOption.full else "ci"
    report = run_fuzz(examples=examples, seed=seed, profile=chosen)
    typer.echo(render_fuzz_report(report), nl=False)
    if not report.ok:
        raise typer.Exit(code=1)


def _save(save_dir: str, report: AttackReport, record: RunRecord, *, quiet: bool) -> None:
    """Write `<ID>.run.json` and `<ID>.report.json`; paths are echoed as the user typed them."""
    target = Path(save_dir)
    target.mkdir(parents=True, exist_ok=True)
    files = {
        f"{report.attack_id}.run.json": record.model_dump_json(indent=2),
        f"{report.attack_id}.report.json": report.model_dump_json(indent=2),
    }
    for name, text in files.items():
        (target / name).write_text(text + "\n", encoding="utf-8")
        typer.echo(f"saved {save_dir.rstrip('/')}/{name}", err=quiet)


@app.command()
def attack(
    attack_id: Annotated[
        str | None, typer.Argument(help="A1..A14 (attack) or B1..B4 (benign control).")
    ] = None,
    list_only: Annotated[bool, typer.Option("--list", help="List the attack library.")] = False,
    run_all: Annotated[bool, typer.Option("--all", help="Run A1..A14 then B1..B4.")] = False,
    monitor: Annotated[
        MonitorOption, typer.Option("--monitor", help="real is the default; fake replays fixtures.")
    ] = MonitorOption.real,
    as_json: Annotated[bool, typer.Option("--json", help="Print the report as JSON.")] = False,
    save_dir: Annotated[
        str | None, typer.Option("--save-dir", help="Write <ID>.run.json and <ID>.report.json.")
    ] = None,
) -> None:
    """Run attacks through the monitor and compare every outcome with the fixture.

    Exit codes: 0 every outcome matches; 1 at least one MISMATCH (known real-monitor deviations
    count); 2 usage error or unknown id.
    """
    if int(attack_id is not None) + int(list_only) + int(run_all) != 1:
        _usage_error("give an attack id, --list or --all")
    if list_only:
        typer.echo(render_attack_list(), nl=False)
        return
    choice: MonitorChoice = "fake" if monitor is MonitorOption.fake else "real"
    ids = (
        [*(f.case.id for f in ALL_ATTACKS), *(c.control_id for c in ALL_CONTROLS)]
        if run_all
        else [attack_id or ""]
    )
    runs: list[tuple[AttackReport, RunRecord]] = []
    for item in ids:
        try:
            runs.append(build_report(item, choice))
        except AttackNotFoundError:
            _usage_error(f"unknown attack id: {item}")
    reports = [report for report, _ in runs]
    if as_json:
        payload = [r.model_dump(mode="json") for r in reports] if run_all else None
        text = (
            json.dumps(payload, indent=2) + "\n"
            if payload is not None
            else reports[0].model_dump_json(indent=2) + "\n"
        )
        typer.echo(text, nl=False)
    elif run_all:
        typer.echo(render_attack_table(reports), nl=False)
    else:
        typer.echo(render_attack_report(reports[0]), nl=False)
    if save_dir is not None:
        for report, record in runs:
            _save(save_dir, report, record, quiet=as_json)
    if not all(report.ok for report in reports):
        raise typer.Exit(code=1)
