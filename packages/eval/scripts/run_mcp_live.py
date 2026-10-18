"""Manual live run: a real Claude Code agent against the MCP eval servers, with and without NOTARY.

    uv run --no-sync python packages/eval/scripts/run_mcp_live.py --confirm-live --rounds 20

For every task and lane (`undefended`: the agent talks to the server; `notary`: through
`notary-mcp-proxy`) it starts `claude -p ... --output-format stream-json` in a fresh sandbox,
reads the MCP server's own call log and judges the attacker goal and the user goal on it. It
writes `results/mcp/<date>.json` (an `McpLiveReport`: the `EvalResults` of both lanes, the cells
with 95% Wilson intervals, the model(s) and the Claude Code version) and `<date>.md` (the table).

This costs model calls and needs a logged-in `claude`. It never runs in tests or in the gate
(`--confirm-live` is required; `--dry-run` only prints the commands). A live model is not
deterministic: quote the numbers with their date, model and Claude Code version only, and never
use them as a test.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from datetime import date as calendar
from pathlib import Path

from notary_eval.mcp_eval import (
    LANES,
    SERVERS,
    AgentRun,
    AgentRunner,
    LiveRound,
    McpLane,
    McpTask,
    build_report,
    claude_argv,
    load_tasks,
    markdown,
    materialize,
    mcp_config,
    run_live_plan,
)

RESULTS = Path(__file__).resolve().parents[1] / "results" / "mcp"
DEFAULT_ROUNDS = 20
TIMEOUT_SECONDS = 600.0
TIMED_OUT = 124


def claude_runner(timeout_seconds: float = TIMEOUT_SECONDS) -> AgentRunner:
    """Runs the argv as a child process; a run that exceeds the timeout counts as failed."""

    def run(argv: Sequence[str], cwd: Path) -> AgentRun:
        try:
            done = subprocess.run(
                list(argv),
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as expired:
            partial = expired.stdout.decode("utf-8", "replace") if expired.stdout else ""
            return AgentRun(tuple(partial.splitlines()), TIMED_OUT)
        return AgentRun(tuple(done.stdout.splitlines()), done.returncode)

    return run


def claude_version(executable: str) -> str | None:
    """The first line of `claude --version`, or none when it cannot be run."""
    try:
        done = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = done.stdout.strip().splitlines()
    return lines[0] if done.returncode == 0 and lines else None


def select_tasks(task_ids: Sequence[str] | None) -> tuple[McpTask, ...]:
    """The tasks to run: the ones named, else every task whose server logs its own calls."""
    tasks = load_tasks()
    if not task_ids:
        return tuple(task for task in tasks if SERVERS[task.server].logs)
    by_id = {task.task_id: task for task in tasks}
    unknown = [name for name in task_ids if name not in by_id]
    if unknown:
        raise SystemExit(f"unknown task(s): {', '.join(unknown)}; known: {', '.join(by_id)}")
    chosen = tuple(by_id[name] for name in task_ids)
    silent = [task.task_id for task in chosen if not SERVERS[task.server].logs]
    if silent:
        raise SystemExit(f"scripted only (the server keeps no call log): {', '.join(silent)}")
    return chosen


def dry_run(tasks: Sequence[McpTask], lanes: Sequence[McpLane], executable: str) -> list[str]:
    """The command of round 0 of each task and lane, with real (temporary) config files."""
    lines: list[str] = []
    with tempfile.TemporaryDirectory(prefix="notary-mcp-dry-") as scratch:
        for task in tasks:
            for lane in lanes:
                workdir = Path(scratch) / f"{task.task_id}-{lane}"
                workdir.mkdir()
                setup = materialize(task.server, workdir)
                config = workdir / "mcp.json"
                config.write_text(
                    json.dumps(mcp_config(task, setup, defended=lane == "notary")), encoding="utf-8"
                )
                argv = claude_argv(task, config, setup.root, executable=executable)
                lines.append(f"{task.task_id} [{lane}]: {' '.join(repr(part) for part in argv)}")
    return lines


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: AgentRunner | None = None,
    version: Callable[[str], str | None] = claude_version,
    today: Callable[[], str] = lambda: calendar.today().isoformat(),
) -> int:
    parser = argparse.ArgumentParser(prog="run_mcp_live", description=__doc__)
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, help="per task and lane")
    parser.add_argument("--tasks", help="comma-separated task ids (default: every logging server)")
    parser.add_argument("--lanes", default=",".join(LANES), help="comma-separated lanes")
    parser.add_argument("--out", type=Path, default=RESULTS, help="directory for the results")
    parser.add_argument("--claude", default="claude", help="the Claude Code executable")
    parser.add_argument("--max-turns", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=TIMEOUT_SECONDS, help="seconds per round")
    parser.add_argument("--confirm-live", action="store_true", help="really call the live model")
    parser.add_argument("--dry-run", action="store_true", help="print the commands and stop")
    args = parser.parse_args(argv)
    if args.rounds < 1:
        parser.error("--rounds must be at least 1")
    lanes = [name for name in str(args.lanes).split(",") if name]
    unknown_lanes = [name for name in lanes if name not in LANES]
    if unknown_lanes:
        parser.error(f"unknown lane(s): {', '.join(unknown_lanes)}; known: {', '.join(LANES)}")
    chosen_lanes: list[McpLane] = [lane for lane in LANES if lane in lanes]
    names = [name for name in str(args.tasks or "").split(",") if name]
    tasks = select_tasks(names)
    executable = str(args.claude)
    if args.dry_run:
        print("\n".join(dry_run(tasks, chosen_lanes, executable)))
        return 0
    if not args.confirm_live:
        print(
            "This calls a live model for "
            f"{len(tasks) * len(chosen_lanes) * args.rounds} round(s). "
            "Re-run with --confirm-live (or --dry-run to see the commands).",
            file=sys.stderr,
        )
        return 2

    def progress(played: LiveRound) -> None:
        state = "ok" if played.completed else "NOT COMPLETED"
        print(
            f"{played.task_id} [{played.lane}] round {played.round}: {state}; "
            f"attack={played.result.attack_succeeded} task={played.result.utility} "
            f"blocked={played.blocked_calls}",
            file=sys.stderr,
            flush=True,
        )

    run_date = today()
    with tempfile.TemporaryDirectory(prefix="notary-mcp-live-") as scratch:
        rounds = run_live_plan(
            tasks,
            args.rounds,
            runner=runner or claude_runner(args.timeout),
            workroot=Path(scratch),
            lanes=chosen_lanes,
            max_turns=args.max_turns,
            executable=executable,
            on_round=progress,
        )
    report = build_report(tasks, rounds, date=run_date, planned=args.rounds)
    if report.claude_version is None:
        report = report.model_copy(update={"claude_version": version(executable)})
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{run_date}.json").write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    table = markdown(report)
    header = (
        f"Live run {run_date}, Claude Code {report.claude_version or 'unknown'}, "
        f"model {', '.join(report.models) or 'unknown'}, "
        f"{args.rounds} round(s) planned per cell.\n\n"
    )
    (out / f"{run_date}.md").write_text(header + table + "\n", encoding="utf-8")
    print(header + table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
