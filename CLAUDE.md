# NOTARY — repo rules

## What NOTARY is

- A deterministic security layer that stops indirect prompt injection in AI agents.
- The user's intent is frozen into an `IntentContract` (allowed tools, per-parameter markers, effect budget).
- Every value carries a provenance `Label` (origin, integrity, readers); raw content never reaches the monitor.
- A pure reference monitor decides each proposed tool call: ALLOW, ESCALATE or BLOCK, with ordered reasons.
- Every decision is logged in a tamper-evident audit hash chain and shown live in the "Trust X-ray" UI.

## Package map and allowed dependency directions

```
apps/web        -> @notary/ui, @notary/client, @notary/schema
apps/server     -> notary_core, notary_world, notary_mcp_proxy
packages/ui     -> @notary/schema
packages/client -> @notary/schema
packages/schema -> (nothing)
packages/core   -> (pydantic + stdlib only)
packages/mcp-proxy, cli, eval, world -> notary_core   (cli/eval may also use notary_world)
```

Python layers (import-linter, root `pyproject.toml`): `server | cli | eval` > `mcp_proxy | world` > `core`.
TS direction is enforced by `eslint-plugin-boundaries` (`packages/config-eslint/boundaries.js`).
`config-typescript` and `config-eslint` are tooling only. Violations fail `lint`.

## Hard rules

- **`notary_core` is pure and deterministic. Never add I/O, networking, randomness, clock reads, env access or LLM calls to it.**
  `packages/core/tests/test_core_purity.py` and an import-linter contract enforce this.
- **Types originate in Pydantic.** Never hand-edit generated files (`packages/schema/json/**`,
  `packages/schema/src/generated/**`, `packages/client/openapi.json`, `packages/client/src/generated/**`,
  `packages/world/fixtures/streams/**`, `packages/world/fixtures/commands/**`). Change the model in `notary_core`, then run `pnpm schema:generate`.
  If a generator produces poor output, fix the Pydantic model (or the Pydantic-side schema generator), not the output.
- No `any` in TypeScript (`@typescript-eslint/no-explicit-any` is an error). No `Any` in Python (pyright strict + ruff ban on `typing.Any`).
- All models: `extra="forbid"`, `frozen=True`, strict, discriminated unions with a literal `type`/`kind`.
- Python packages are consumed from `src/` through uv; TS libraries (`schema`, `client`, `ui`) are consumed as source (no build step).

## Commands

```
pnpm install && uv sync          # once, from a clean clone
pnpm dev                         # server (:8000) + web (:3000), open /x-ray
pnpm schema:generate             # core -> JSON Schema -> TS types + Zod; OpenAPI -> client types; event fixtures
pnpm schema:check                # regenerate and fail on drift (restores files when it fails)
pnpm --filter @notary/cli cp1    # CP1 proof: notary attack --all and notary fuzz (ci profile)
uv run --no-sync pytest apps/server/tests/test_cp2.py   # CP2 proof: cassette replay, no network
uv run --no-sync python apps/server/scripts/record_cassettes.py [--live]   # re-record cassettes (--live needs ANTHROPIC_API_KEY)
```

**Before committing run:** `pnpm schema:generate && pnpm turbo run lint typecheck test build && pnpm schema:check`.
Use `uv run --no-sync` inside package scripts (parallel `uv run` calls corrupt the env); run `uv sync` yourself.

## The monitor's check order

`monitor.decide(contract, proposal, values, ledger) -> Decision`. `Decision.reasons` follows this order (`CHECK_ORDER`):

1. **scope** — tool and parameters are within the contract
2. **irreversibility** — irreversible effects need stronger evidence
3. **origin** — argument labels satisfy the per-parameter markers
4. **corroboration** — untrusted-origin values are corroborated by the ledger
5. **confidentiality** — egress / readers: data may not flow to non-readers
6. **budget** — the call fits the remaining effect budget

Any failing check → BLOCK; otherwise any escalating check → ESCALATE; otherwise ALLOW.

## Workflow

- Never commit to `main` directly. Branch from `main` (`p<phase>/<slug>`, e.g. `p1/ledger`), open a pull request, merge only after review.
- One PR per issue; put `Closes #<n>` in the PR body. Contract changes (label `contract-change`) need the announcement from phase.md P0b.
- Run the commands under "Commands" before pushing; the CI workflow is currently removed, so the PR author is the gate.

## Docs

- `docs/architecture.md` — components, monitor decision order, invariants I1-I6, event contract
- `docs/threat-model.md` — attacks A1-A14, prior art, verification plan, limitations
- `docs/demo.md` — determinism, Trust X-ray, judge playground, stage script
- `docs/phase.md` — build phases P0, P0b, P1, P2, P3a-P3d, P4-P7, cut line, risks
- `docs/decisions.md` — tool/design choices and conventions

When behavior, invariants, event types or package boundaries change, update the relevant doc in the same commit.
