"""Run NOTARY on AgentDojo (banking and Slack): see `notary_eval.dojo_cli` for the options.

    uv run --no-sync python packages/eval/scripts/run_agentdojo.py --dry-run

A model agent costs money and needs `--confirm-live`; the default scripted agent is free.
"""

from notary_eval.dojo_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
