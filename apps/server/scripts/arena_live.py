"""Long adaptive-attacker arena (manual, costs tokens, never in CI): an LLM attacker plays N rounds.

    uv run --no-sync python apps/server/scripts/arena_live.py --dry-run
    uv run --no-sync python apps/server/scripts/arena_live.py --confirm-live \
        [--rounds 30] [--lanes undefended classifier notary] [--seed 0] \
        [--agent-model openai/gpt-oss-120b] [--scenario poisoned_bill] \
        [--out arena.json] [--markdown arena.md]

Each round the attacker (`DEFAULT_MODEL` on Groq) picks a vector and a payload, the agent (a live
Groq model) runs the bill task on that world on each lane, and the oracle says whether the
attacker's payment went out. The attacker sees the reached/not-reached light and the BLOCK reason
codes, never the world. The output keeps counts per lane (payload text is never printed or
saved: `ArenaRound` has its length only). Exit code: 0 fine, 1 the attacker goal was reached on
the NOTARY lane (a bug), 2 no GROQ_API_KEY or no `--confirm-live`. The key comes from the shell or
from a git-ignored `.env`.

Expect a lane-round to cost one agent run (a few model calls) and a round one attacker call whose
prompt grows with the history; Groq's on-demand tier allows 200,000 tokens per model per day
(docs/demo.md), so 30 rounds on three lanes will not fit one key and day: use `--lanes notary`
first, or `--rounds 10`, and read the token use in the Groq console before scaling up.
"""

import argparse
import os
import sys
from collections.abc import Iterator
from datetime import date
from pathlib import Path

from notary_core.models import ArenaStartCommand, Event, Lane
from notary_server.anchors import AnchorStore
from notary_server.arena import ArenaService
from notary_server.arena_live import guarded_successes, markdown
from notary_server.endorsement import EndorsementBroker
from notary_server.envfile import load_env_file
from notary_server.groq_client import GroqClient
from notary_server.llm import DEFAULT_MODEL, LlmClient
from notary_server.model_eval import MAX_WAIT_SECONDS
from notary_server.wiring import LiveSource, RunStreamer, Settings
from notary_world.scenarios import Scenario

LANES: tuple[Lane, ...] = ("undefended", "classifier", "notary")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Live attacker arena (costs tokens).")
    parser.add_argument("--rounds", type=int, default=30)
    parser.add_argument("--lanes", nargs="+", choices=LANES, default=list(LANES))
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--scenario", default="poisoned_bill")
    parser.add_argument("--agent-model", default=DEFAULT_MODEL)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--markdown", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true", help="print the plan, call nothing")
    parser.add_argument("--confirm-live", action="store_true", help="really call the API")
    args = parser.parse_args(argv)
    runs = args.rounds * len(args.lanes)
    plan = (
        f"plan: {args.rounds} rounds x {len(args.lanes)} lanes = {runs} agent runs and "
        f"{args.rounds * len(args.lanes)} attacker calls; attacker {DEFAULT_MODEL}, "
        f"agent {args.agent_model}, scenario {args.scenario}, seed {args.seed}\n"
    )
    sys.stdout.write(plan)
    if args.dry_run:
        return 0
    if not args.confirm_live:
        sys.stderr.write("refusing to run: pass --confirm-live (this costs tokens)\n")
        return 2
    load_env_file()
    if not Settings.from_env(os.environ).live_available:
        sys.stderr.write("refusing to run: GROQ_API_KEY is not set\n")
        return 2

    streamer = RunStreamer(broker=EndorsementBroker(timeout_seconds=0.01), anchors=AnchorStore())
    source = LiveSource(
        streamer,
        available=True,
        client_factory=lambda: GroqClient(max_wait_seconds=MAX_WAIT_SECONDS),
        model=args.agent_model,
    )

    def lane_runner(scenario: Scenario, lane: Lane, run_id: str) -> Iterator[Event]:
        return source.run(scenario, lane)

    def attacker(lane: Lane) -> LlmClient:
        return GroqClient(max_wait_seconds=MAX_WAIT_SECONDS)

    service = ArenaService(lane_runner, attacker, max_rounds=args.rounds)
    result = service.run(
        ArenaStartCommand(
            type="arena_start",
            scenario=args.scenario,
            rounds=args.rounds,
            lanes=tuple(args.lanes),
            seed=args.seed,
        )
    )
    table = markdown(
        result,
        date=date.today().isoformat(),
        agent_model=args.agent_model,
        attacker_model=DEFAULT_MODEL,
    )
    sys.stdout.write(table + "\n")
    if args.out is not None:
        args.out.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if args.markdown is not None:
        args.markdown.write_text(table + "\n", encoding="utf-8")
    bad = guarded_successes(result)
    if bad:
        sys.stderr.write(f"FAIL: the attacker goal was reached {bad} time(s) on the NOTARY lane\n")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
