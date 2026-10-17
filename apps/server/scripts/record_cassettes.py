"""Record the cassettes the stage run replays, into packages/world/fixtures/cassettes/.

    uv run --no-sync python scripts/record_cassettes.py            # scripted: no key, no network
    uv run --no-sync python scripts/record_cassettes.py --live     # the Groq API (costs tokens)

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
from notary_server.recording import record_all, scripted_cassettes
from notary_server.wiring import Settings
from notary_world.loader import FIXTURES_DIR
from notary_world.models import Cassette
from notary_world.scenarios import Scenario

TARGET = FIXTURES_DIR / "cassettes"


def live_cassettes() -> dict[str, Cassette]:
    def agent(scenario: Scenario, lane: Lane) -> LlmClient:
        return GroqClient()

    def attacker(lane: Lane) -> LlmClient:
        return GroqClient()

    return record_all(model=DEFAULT_MODEL, agent=agent, attacker=attacker, compiler=GroqClient)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Record the stage-run cassettes.")
    parser.add_argument("--live", action="store_true", help="record from the Groq API")
    parser.add_argument("--out", type=Path, default=TARGET, help="directory to write into")
    args = parser.parse_args(argv)
    load_env_file()
    if args.live and not Settings.from_env(os.environ).live_available:
        sys.stderr.write("refusing to record live: GROQ_API_KEY is not set\n")
        return 2
    cassettes = live_cassettes() if args.live else scripted_cassettes()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, cassette in cassettes.items():
        (args.out / f"{name}.json").write_text(cassette_json(cassette), encoding="utf-8")
        sys.stdout.write(f"{name}.json: {len(cassette.entries)} entries, model {cassette.model}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
