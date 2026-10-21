"""The `run_agentdojo.py` command line: plan, guard, run, resume, export.

    # free, offline: a scripted agent against the committed snapshot (what the tests run)
    uv run --no-sync python packages/eval/scripts/run_agentdojo.py --dry-run
    uv run --no-sync python packages/eval/scripts/run_agentdojo.py --out-dir /tmp/dojo

    # free, AgentDojo's own checkers (needs the optional package for this one command)
    uv run --no-sync --with agentdojo==0.1.35 python packages/eval/scripts/run_agentdojo.py \\
        --source agentdojo

    # costs model calls: needs the provider key in the environment and --confirm-live
    uv run --no-sync --with agentdojo==0.1.35 python packages/eval/scripts/run_agentdojo.py \\
        --agent model --model groq:openai/gpt-oss-120b --confirm-live

Nothing that calls a model runs without `--confirm-live`; `--dry-run` lists the plan and the rough
cost and calls nothing. Every finished run is appended to `runs.jsonl` in the output directory, so a
stopped run resumes where it stopped (rerun the same command).
"""

import argparse
import re
from collections.abc import Callable, Sequence
from datetime import date as calendar
from pathlib import Path

from notary_core.models import Lane
from notary_eval.dojo_live import PINNED_VERSION, agentdojo_available, agentdojo_version
from notary_eval.dojo_live_run import MissingKeyError, run_all_live
from notary_eval.dojo_report import write_outputs
from notary_eval.dojo_run import (
    ATTACK,
    RunConfig,
    make_report,
    plan_runs,
    run_all_offline,
    selected_user_tasks,
)
from notary_eval.dojo_types import (
    LANES,
    SUITES,
    AgentKind,
    ApprovalPolicy,
    DojoRun,
    DojoSnapshot,
    SourceKind,
)

PACKAGE = Path(__file__).resolve().parents[2]
SNAPSHOT = PACKAGE / "fixtures" / "agentdojo" / "snapshot-v1.2.2.json"
RESULTS = PACKAGE / "results" / "agentdojo"
CALLS_PER_RUN = 8
INPUT_TOKENS_PER_CALL = 3_000
"""Rough, for the dry run only: a tool-calling run makes a handful of calls that each resend the
conversation. The real numbers are in the report (`model_calls`)."""
EXIT_REFUSED = 2

COST_WARNING = """\
COST WARNING: --agent model sends real requests to {model}. {runs} runs are planned, which is
roughly {calls:,} model calls and {tokens:,} input tokens (a rough estimate, not a quote; the
report records the real number of calls). Check your provider's price for those tokens and your
budget first. Use --max-tasks to try a small slice, and --lane to run one lane at a time."""


def load_snapshot(path: Path = SNAPSHOT) -> DojoSnapshot:
    return DojoSnapshot.model_validate_json(path.read_text(encoding="utf-8"))


def read_runs(path: Path) -> dict[str, DojoRun]:
    """The runs already finished in `path` (errored ones are retried, so they are left out)."""
    if not path.exists():
        return {}
    runs = (
        DojoRun.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    return {run.key: run for run in runs if run.status == "ok"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        description="Run NOTARY on AgentDojo (banking and Slack) and export the results."
    )
    cli.add_argument("--suite", action="append", choices=SUITES, help="repeat; default: both")
    cli.add_argument("--lane", action="append", choices=LANES, help="repeat; default: all three")
    cli.add_argument("--agent", choices=("scripted", "model"), default="scripted")
    cli.add_argument("--model", help="groq:<id>, openai:<id>, anthropic:<id> or an AgentDojo name")
    cli.add_argument("--source", choices=("snapshot", "agentdojo"), default=None)
    cli.add_argument("--attack", default=ATTACK)
    cli.add_argument("--max-tasks", type=int, default=None, help="first N user tasks per suite")
    cli.add_argument("--approval", choices=("reject", "oracle"), default="reject")
    cli.add_argument("--dry-run", action="store_true", help="list the plan, call nothing")
    cli.add_argument("--confirm-live", action="store_true", help="required for any model call")
    cli.add_argument("--out-dir", type=Path, default=None)
    cli.add_argument("--snapshot", type=Path, default=SNAPSHOT)
    cli.add_argument("--date", default=None, help="YYYY-MM-DD, default today")
    cli.add_argument("--sample", action="store_true", help="label the output SAMPLE, not a result")
    return cli


def describe_plan(snapshot: DojoSnapshot, config: RunConfig, out: Callable[[str], None]) -> int:
    specs = plan_runs(snapshot, config)
    out(
        f"AgentDojo {snapshot.benchmark} (agentdojo=={snapshot.agentdojo_version}), "
        f"attack {config.attack}, escalations answered by: {config.approval}"
    )
    for name in config.suites:
        suite = snapshot.suite(name)
        tasks = selected_user_tasks(suite, config)
        out(f"  {name}: {len(tasks)} user tasks x {len(suite.injection_tasks)} injection tasks")
        for task in tasks:
            out(f"    {task.task_id}: {task.prompt[:90]}")
        out("    injection: " + ", ".join(t.task_id for t in suite.injection_tasks))
    out(f"lanes: {', '.join(config.lanes)}")
    out(f"planned runs: {len(specs)}")
    return len(specs)


def main(argv: Sequence[str] | None = None, out: Callable[[str], None] = print) -> int:
    args = parser().parse_args(argv)
    agent: AgentKind = args.agent
    source: SourceKind = args.source or ("agentdojo" if agent == "model" else "snapshot")
    if agent == "model":
        if not args.model:
            out("--agent model needs --model")
            return EXIT_REFUSED
        source = "agentdojo"
    elif args.model:
        out("--model is only for --agent model (the scripted agent calls no model)")
        return EXIT_REFUSED
    approval: ApprovalPolicy = args.approval
    lanes: tuple[Lane, ...] = tuple(args.lane) if args.lane else LANES
    config = RunConfig(
        suites=tuple(args.suite) if args.suite else SUITES,
        lanes=lanes,
        max_tasks=args.max_tasks,
        approval=approval,
        attack=args.attack,
    )
    snapshot = load_snapshot(args.snapshot)
    planned = describe_plan(snapshot, config, out)
    if agent == "model":
        out(
            COST_WARNING.format(
                model=args.model,
                runs=planned,
                calls=planned * CALLS_PER_RUN,
                tokens=planned * CALLS_PER_RUN * INPUT_TOKENS_PER_CALL,
            )
        )
    if args.dry_run:
        out("dry run: nothing was called")
        return 0
    if agent == "model" and not args.confirm_live:
        out("refused: a model call needs --confirm-live (nothing was called)")
        return EXIT_REFUSED
    if source == "agentdojo":
        if not agentdojo_available():
            out(
                "the optional agentdojo package is missing: add "
                f"`--with agentdojo=={PINNED_VERSION}`"
            )
            return EXIT_REFUSED
        if agentdojo_version() != snapshot.agentdojo_version:
            out(
                f"agentdojo {agentdojo_version()} is installed but the snapshot is "
                f"{snapshot.agentdojo_version}; export a new snapshot or install the pinned one"
            )
            return EXIT_REFUSED
    day = args.date or calendar.today().isoformat()
    label = (
        "SAMPLE: AgentDojo banking and Slack, scripted agent"
        if args.sample
        else f"AgentDojo banking and Slack, {args.model or 'scripted agent'}"
    )
    out_dir: Path = args.out_dir or RESULTS / (
        "sample" if args.sample else f"{day}-{_slug(args.model or f'scripted-{source}')}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    log = out_dir / "runs.jsonl"
    done = read_runs(log)
    if done:
        out(f"resuming: {len(done)} runs already in {log}")

    def record(run: DojoRun) -> None:
        with log.open("a", encoding="utf-8") as handle:
            handle.write(run.model_dump_json() + "\n")

    try:
        if source == "snapshot":
            runs = run_all_offline(snapshot, config, done=done, on_run=record)
        else:
            runs = run_all_live(
                snapshot,
                config,
                agent,
                args.model,
                benchmark=snapshot.benchmark,
                done=done,
                on_run=record,
            )
    except MissingKeyError as missing:
        out(f"refused: {missing}")
        return EXIT_REFUSED
    notes = (
        ("Scripted agent: utility and attack success are judged on the ground-truth calls.",)
        if source == "snapshot"
        else ()
    )
    report = make_report(
        runs,
        snapshot=snapshot,
        config=config,
        agent=agent,
        source=source,
        model=args.model,
        date=day,
        label=label,
        sample=args.sample,
        planned=planned,
        notes=notes,
    )
    (out_dir / "report.json").write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    written = write_outputs(report, out_dir)
    out(f"wrote {out_dir / 'report.json'} and " + ", ".join(p.name for p in written))
    return 0
