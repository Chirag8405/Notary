"""Write the charts and the deck numbers from an exported AgentDojo report, by script.

    uv run --no-sync python packages/eval/scripts/agentdojo_report.py \\
        packages/eval/results/agentdojo/sample/report.json

Reads `report.json` (an `AgentDojoReport`) and writes `numbers.md`, `asr.svg` and `utility.svg`
next to it (or into `--out-dir`). Nothing is typed by hand.
"""

import argparse
from pathlib import Path

from notary_eval.dojo_report import write_outputs
from notary_eval.dojo_types import AgentDojoReport


def main() -> int:
    cli = argparse.ArgumentParser(description="Charts and deck numbers from a report.json.")
    cli.add_argument("report", type=Path)
    cli.add_argument("--out-dir", type=Path, default=None)
    args = cli.parse_args()
    report = AgentDojoReport.model_validate_json(args.report.read_text(encoding="utf-8"))
    for path in write_outputs(report, args.out_dir or args.report.parent):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
