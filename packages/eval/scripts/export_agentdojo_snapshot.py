"""Copy the AgentDojo banking and Slack suites into the offline snapshot fixture.

    uv run --no-sync --with agentdojo==0.1.35 \\
        python packages/eval/scripts/export_agentdojo_snapshot.py

Needs the optional `agentdojo` package (not a dependency of the repo); no model call.
It writes `fixtures/agentdojo/snapshot-<benchmark>.json`, the file the offline harness, the
tests and the SAMPLE results run on. AgentDojo is MIT licensed; the licence line travels with it.
"""

import argparse
from pathlib import Path

from notary_eval.dojo_live import DEFAULT_BENCHMARK, build_snapshot
from notary_eval.dojo_types import SUITES

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "agentdojo"


def main() -> int:
    parser = argparse.ArgumentParser(description="Export the AgentDojo task snapshot.")
    parser.add_argument("--benchmark", default=DEFAULT_BENCHMARK)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    snapshot = build_snapshot(SUITES, args.benchmark)
    out = args.out or FIXTURES / f"snapshot-{args.benchmark}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(snapshot.model_dump_json(indent=1) + "\n", encoding="utf-8")
    sizes = ", ".join(
        f"{s.suite}: {len(s.user_tasks)} user / {len(s.injection_tasks)} injection tasks"
        for s in snapshot.suites
    )
    print(f"wrote {out} ({sizes})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
