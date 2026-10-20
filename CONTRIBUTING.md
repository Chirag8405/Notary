# Contributing to NOTARY

Thanks for helping. NOTARY is a security layer, so the bar is correctness first: a change that weakens a guarantee is rejected even if every test passes. Read [`CLAUDE.md`](CLAUDE.md) first. It holds the rules this guide summarizes.

## Setup

Requirements: Node >= 24, pnpm >= 12, [uv](https://docs.astral.sh/uv/) and Python 3.12.

```sh
pnpm install && uv sync
pnpm dev
```

The server runs on <http://localhost:8000> and the web app on <http://localhost:3000>. Run `uv sync` yourself and call Python through `uv run --no-sync`; parallel `uv run` calls corrupt the environment.

## Rules that are not negotiable

- **`notary_core` stays pure and deterministic.** No I/O, networking, randomness, clock reads, env access or LLM calls. `packages/core/tests/test_core_purity.py` and an import-linter contract enforce it.
- **Types originate in Pydantic.** Change the model in `notary_core`, then run `pnpm schema:generate`. Never hand-edit generated files (`packages/schema/json/**`, `packages/schema/src/generated/**`, `packages/client/openapi.json`, `packages/client/src/generated/**`, `packages/world/fixtures/streams/**`, `packages/world/fixtures/commands/**`, `packages/mcp-proxy/schema/**`).
- **No `any` in TypeScript and no `Any` in Python.**
- **All models** use `extra="forbid"`, `frozen=True`, strict mode and discriminated unions with a literal `type` or `kind`.
- **Respect the package map.** Dependency directions are enforced by import-linter and `eslint-plugin-boundaries`; a violation fails `lint`.
- **Keep the docs true.** When behavior, invariants, event types or package boundaries change, update the matching file in `docs/` in the same commit.

## Workflow

1. Never commit to `main`. Branch from `main` as `p<phase>/<slug>`, for example `p1/ledger`.
2. Make one pull request per issue and put `Closes #<n>` in the description.
3. Changes to the contract need the `contract-change` label and the announcement described in `docs/phase.md` (P0b).
4. Merge only after review.

Write [conventional commits](https://www.conventionalcommits.org/) such as `feat(core): add ledger match` or `fix(web): keep the socket open`. Keep the subject short and use the body to say why.

## Before you push

Run the full gate locally:

```sh
pnpm schema:generate && pnpm turbo run lint typecheck test build && pnpm schema:check
pnpm format:check
```

Also run the CP1 proof (`pnpm --filter @notary/cli cp1`) when you touch the monitor, the world or the evaluation harness, and `pnpm playground:fixtures:check` when you touch the server or the playground.

If `format:check` fails, run `pnpm format`. Recorded fixtures and generated files are excluded from prettier on purpose; do not reformat them.

## What CI checks

`.github/workflows/ci.yml` runs the same checks in levels, cheapest first. A level starts only when the previous one is green.

| Level | Checks                                                   |
| ----- | -------------------------------------------------------- |
| L1    | prettier, ruff, ruff format, import-linter               |
| L2    | eslint with boundaries, pyright, tsc                     |
| L3    | pytest and vitest                                        |
| L4    | generated files and fixtures in sync, CP1 attacks + fuzz |
| L5    | build                                                    |

`CI passed` is the single check that must be green before merging.

## Tests

- Python tests live in each package's `tests/` and run with `uv run --no-sync pytest`. They use `hypothesis` for property tests.
- Web and TypeScript tests use `vitest`.
- LLM behavior is tested from recorded cassettes, so tests never touch the network. To re-record, see `apps/server/scripts/record_cassettes.py` (`--live` needs `GROQ_API_KEY` in your shell or a git-ignored `.env`). Never commit secrets.

## Reporting a vulnerability

If you find a way to bypass the monitor, do not open a public issue. Contact a maintainer privately first.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
