"""Record the cassettes the stage run replays, into packages/world/fixtures/cassettes/.

    uv run --no-sync python scripts/record_cassettes.py              # scripted set (default)
    uv run --no-sync python scripts/record_cassettes.py --set real   # the Groq API (costs tokens)
    uv run --no-sync python scripts/record_cassettes.py --set synthetic --out DIR  # test-only

Cassette sets (`--set`):
  scripted   (default) fixed turns, no key, no network; writes packages/world/fixtures/cassettes
             (the committed set; the CP2 tests that need a hijacked agent replay it).
  real       a real model on Groq; needs GROQ_API_KEY; writes
             packages/world/fixtures/cassettes-real (replay with NOTARY_CASSETTE_DIR). `--live` is
             the old spelling and means `--set real` with the output the committed scripted
             directory unless `--out` is given.
  synthetic  a scripted agent that ignores the injection (a stand-in for a model that is not
             hijacked); test-only, needs `--out`, never committed.
`--out DIR` overrides the directory of any set.

Scripted mode writes cassettes whose responses are fixed turns (model "scripted-v1"); their keys
are the real prompt hashes, so the replay is real, but no model produced them. `--live` calls the
Groq API with `DEFAULT_MODEL`, refuses to run without `GROQ_API_KEY`, and is manual: it never
runs in CI. The key comes from the shell or from a git-ignored `.env` (see `.env.example`).
Re-record whenever the model, the agent system prompt, the tool descriptions or the rendering
format change (the key covers all of them).
"""

import argparse
import os
import sys
from pathlib import Path

from notary_core.models import Lane
from notary_server.envfile import load_env_file
from notary_server.groq_client import GroqClient
from notary_server.llm import DEFAULT_MODEL, LlmClient, cassette_json
from notary_server.recording import record_all, scripted_cassettes, synthetic_cassettes
from notary_server.wiring import Settings
from notary_world.loader import CASSETTES_DIR, REAL_CASSETTES_DIR
from notary_world.models import Cassette
from notary_world.scenarios import Scenario

TARGET = CASSETTES_DIR
REAL_TARGET = REAL_CASSETTES_DIR


def live_cassettes() -> dict[str, Cassette]:
    def agent(scenario: Scenario, lane: Lane) -> LlmClient:
        return GroqClient()

    def attacker(lane: Lane) -> LlmClient:
        return GroqClient()

    return record_all(model=DEFAULT_MODEL, agent=agent, attacker=attacker, compiler=GroqClient)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Record the stage-run cassettes.")
    parser.add_argument(
        "--set",
        dest="cassette_set",
        choices=("scripted", "real", "synthetic"),
        default="scripted",
        help="which cassette set to record (default: scripted)",
    )
    parser.add_argument("--live", action="store_true", help="record from the Groq API")
    parser.add_argument("--out", type=Path, default=None, help="directory to write into")
    args = parser.parse_args(argv)
    live = args.live or args.cassette_set == "real"
    if args.live and args.cassette_set != "real":
        sys.stderr.write("--live without --set real is the old spelling; prefer --set real\n")
    if args.cassette_set == "synthetic" and (live or args.out is None):
        sys.stderr.write("--set synthetic is test-only: give --out and no --live\n")
        return 2
    load_env_file()
    if live and not Settings.from_env(os.environ).live_available:
        sys.stderr.write("refusing to record live: GROQ_API_KEY is not set\n")
        return 2
    out: Path
    if args.out is not None:
        out = args.out
    elif args.cassette_set == "real":
        out = REAL_TARGET
    else:
        out = TARGET
    if args.cassette_set == "synthetic":
        cassettes = synthetic_cassettes()
    else:
        cassettes = live_cassettes() if live else scripted_cassettes()
    args.out = out
    args.out.mkdir(parents=True, exist_ok=True)
    for name, cassette in cassettes.items():
        (args.out / f"{name}.json").write_text(cassette_json(cassette), encoding="utf-8")
        sys.stdout.write(f"{name}.json: {len(cassette.entries)} entries, model {cassette.model}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
