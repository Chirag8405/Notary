"""Record the cassettes the stage run replays, into packages/world/fixtures/cassettes/.

    uv run --no-sync python scripts/record_cassettes.py            # scripted: no key, no network
    ANTHROPIC_API_KEY=... uv run --no-sync python scripts/record_cassettes.py --live

Scripted mode writes cassettes whose responses are fixed turns (model "scripted-v1"); their keys
are the real prompt hashes, so the replay is real, but no model produced them. `--live` calls the
Anthropic API (costs tokens), refuses to run without ANTHROPIC_API_KEY, and is manual: it never
runs in CI. Re-record whenever the agent system prompt, the tool descriptions or the rendering
format change (the key covers all of them).
"""

import argparse
import os
import sys
from pathlib import Path

from notary_core.models import Lane
from notary_server.anthropic_client import AnthropicClient
from notary_server.llm import DEFAULT_MODEL, LlmClient, cassette_json
from notary_server.recording import record_all, scripted_cassettes
from notary_world.loader import FIXTURES_DIR
from notary_world.models import Cassette
from notary_world.scenarios import Scenario

TARGET = FIXTURES_DIR / "cassettes"


def live_cassettes() -> dict[str, Cassette]:
    def agent(scenario: Scenario, lane: Lane) -> LlmClient:
        return AnthropicClient()

    def attacker(lane: Lane) -> LlmClient:
        return AnthropicClient()

    def compiler() -> LlmClient:
        return AnthropicClient()

    return record_all(model=DEFAULT_MODEL, agent=agent, attacker=attacker, compiler=compiler)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Record the stage-run cassettes.")
    parser.add_argument("--live", action="store_true", help="record from the Anthropic API")
    parser.add_argument("--out", type=Path, default=TARGET, help="directory to write into")
    args = parser.parse_args(argv)
    if args.live and not os.environ.get("ANTHROPIC_API_KEY"):
        sys.stderr.write("refusing to record live: ANTHROPIC_API_KEY is not set\n")
        return 2
    cassettes = live_cassettes() if args.live else scripted_cassettes()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, cassette in cassettes.items():
        (args.out / f"{name}.json").write_text(cassette_json(cassette), encoding="utf-8")
        sys.stdout.write(f"{name}.json: {len(cassette.entries)} entries, model {cassette.model}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
