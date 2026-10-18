"""Model-dependence eval (manual, costs tokens, never in CI): attack success per model and lane.

    uv run --no-sync python scripts/model_eval.py [--rounds 20]
        [--models openai/gpt-oss-20b qwen/qwen3.8-27b openai/gpt-oss-120b]
        [--attacks swapped_iban instruction_override payee_update_notice]
        [--max-runs-per-model N] [--out model_eval.json] [--markdown model_eval.md]

Runs each attack on the Undefended, Classifier and NOTARY lanes with a live Groq model, round `n`
on world seed `n - 1`, and prints a Markdown table with a 95% Wilson interval per cell. Exit code:
0 all fine (a model stopped by Groq's daily cap is reported, its partial rounds are kept), 1 the
attacker goal was reached on the NOTARY lane (a bug), 2 no GROQ_API_KEY. The key comes from the
shell or a git-ignored `.env`.
"""

import argparse
import os
import sys
from datetime import date
from pathlib import Path

from notary_core.models import Lane
from notary_server.anchors import AnchorStore
from notary_server.endorsement import EndorsementBroker
from notary_server.envfile import load_env_file
from notary_server.groq_client import GroqClient
from notary_server.model_eval import (
    ATTACKS,
    MAX_WAIT_SECONDS,
    guarded_violations,
    live_runner,
    markdown,
    run_eval,
)
from notary_server.wiring import LiveSource, RunStreamer, Settings

DEFAULT_MODELS = ("openai/gpt-oss-20b", "qwen/qwen3.8-27b", "openai/gpt-oss-120b")
LANES: tuple[Lane, ...] = ("undefended", "classifier", "notary")


def live_source(model: str) -> LiveSource:
    streamer = RunStreamer(broker=EndorsementBroker(timeout_seconds=0.01), anchors=AnchorStore())
    return LiveSource(
        streamer,
        available=True,
        client_factory=lambda: GroqClient(max_wait_seconds=MAX_WAIT_SECONDS),
        model=model,
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Attack success per model and lane.")
    parser.add_argument("--models", nargs="+", default=list(DEFAULT_MODELS))
    parser.add_argument("--attacks", nargs="+", default=[a.attack_id for a in ATTACKS])
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--max-runs-per-model", type=int, default=None)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--markdown", type=Path, default=None)
    args = parser.parse_args(argv)
    load_env_file()
    if not Settings.from_env(os.environ).live_available:
        sys.stderr.write("refusing to run: GROQ_API_KEY is not set\n")
        return 2
    attacks = [a for a in ATTACKS if a.attack_id in args.attacks]
    report = run_eval(
        args.models,
        attacks,
        LANES,
        args.rounds,
        live_runner(live_source),
        date=date.today().isoformat(),
        max_runs_per_model=args.max_runs_per_model,
    )
    table = markdown(report)
    sys.stdout.write(table + "\n")
    if args.out is not None:
        args.out.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if args.markdown is not None:
        args.markdown.write_text(table + "\n", encoding="utf-8")
    bad = guarded_violations(report)
    for cell in bad:
        sys.stderr.write(
            f"FAIL: {cell.model} {cell.attack}: NOTARY lane {cell.hits}/{cell.rounds}\n"
        )
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
