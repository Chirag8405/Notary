# Decisions

Architecture context: [architecture.md](architecture.md). Phases: [phase.md](phase.md).

| Decision                            | Choice                                                                                                         | Why                                                                   | Revisit if                                                    |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------- |
| Monorepo                            | Turborepo + pnpm, with a uv workspace; each Python package has a `package.json` wrapping uv commands           | one task graph and cache across TS and Python                         | Turbo cannot express a needed Python task dependency          |
| Source of types                     | Pydantic v2 in `packages/core`; generated JSON Schema -> TS types + Zod; no hand-written duplicates            | one definition; drift fails CI (`pnpm schema:check`)                  | a construct cannot be generated cleanly (fix the model first) |
| Core purity                         | `notary_core` is pure Python: no I/O, clock, randomness, LLM                                                   | monitor stays small and auditable; deterministic by construction      | never relax; add adapters outside core                        |
| Language for eval and fuzz          | Python                                                                                                         | AgentDojo and Hypothesis are Python                                   | AgentDojo is unavailable                                      |
| Web                                 | Next.js (App Router) + React Flow                                                                              | provenance graph needs a node-graph library                           | React Flow cannot render the required graph                   |
| LLM access                          | raw Anthropic SDK with a small hand-written tool loop; no agent framework                                      | control flow is ours; record/replay is trivial                        | the loop outgrows a few hundred lines                         |
| Model independence demo             | a second non-Claude model (e.g. local Qwen via Ollama), only to demonstrate I6                                 | shows the guarantee does not depend on the model                      | Hijacked Mode alone is judged sufficient                      |
| Policy language                     | hand-written Python rules, not OPA/Cedar                                                                       | six fixed steps; no policy-language surface to audit                  | policies must be user-authored                                |
| Storage                             | SQLite for ledger, audit and world                                                                             | single file, deterministic reset, no server                           | concurrent multi-user deployment                              |
| Server                              | FastAPI + WebSocket event stream                                                                               | Pydantic-native; OpenAPI for REST types                               | event rate exceeds one process                                |
| Delivery                            | Docker Compose + public deploy + offline fallback                                                              | venue connectivity is a risk                                          | n/a                                                           |
| Discriminated unions in JSON Schema | emitted as `anyOf` + `discriminator` (custom `GenerateJsonSchema` in `packages/core/scripts/export_schema.py`) | Pydantic's `oneOf` generates poor Zod                                 | json-schema-to-zod handles `oneOf` well                       |
| TypeScript version                  | pinned to 6.0.3                                                                                                | `typescript-eslint` supports `<6.1` only                              | `typescript-eslint` supports TS 7                             |
| uv in package scripts               | `uv run --no-sync`                                                                                             | parallel `uv run` calls corrupted the shared env; run `uv sync` first | uv serializes syncs                                           |

## Conventions

- IDs (A1-A14, I1-I6, component names, decision-order steps) are stable; never rename them. Tests, code and UI cite them.
- Generated files are never hand-edited ([list](../CLAUDE.md)).
- Docs are updated in the same commit as the behavior change.
