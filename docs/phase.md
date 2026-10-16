# Build phases

Ordered by dependency, not calendar. Components and IDs: [architecture.md](architecture.md). Attacks, invariants, test coverage: [threat-model.md](threat-model.md). Demo surfaces: [demo.md](demo.md).

| Phase | Goal                                                 | Depends on | Date | Status      |
| ----- | ---------------------------------------------------- | ---------- | ---- | ----------- |
| P0    | Foundations                                          | -          | TBD  | done        |
| P1    | Core                                                 | P0         | TBD  | next        |
| P2    | World, attacks, Hijacked Mode, CLI                   | P1         | TBD  | not started |
| P3    | Gateway, Value Store, Compiler, Runner, event stream | P1, P2     | TBD  | not started |
| P4    | Trust X-ray UI                                       | P3         | TBD  | not started |
| P5    | Judge playground                                     | P4         | TBD  | not started |
| P6    | MCP proxy, evals                                     | P3         | TBD  | not started |
| P7    | Hardening and demo prep                              | all        | TBD  | not started |

Critical path: P0 -> P1 -> P2 -> P3 -> P4 -> P7. P5 and P6 branch off and rejoin at P7.

**Cut line** (drop first, in order): attacker arena (P5) -> replay scrubber (P5) -> AgentDojo suites beyond banking (P6) -> MCP proxy clip (P6) -> second non-Claude model (P7). Never cut: monitor, fuzz harness, Hijacked Mode, X-ray decision stream, oracle lights.

## P0 Foundations (done)

- Packages: all; no business logic.
- [x] Turborepo + pnpm + uv workspace; Pydantic -> JSON Schema -> TS types + Zod; drift check; boundaries and import-linter; Docker Compose; CI
- [x] `/x-ray` vertical slice: hard-coded typed event stream -> client -> `DecisionStream` + placeholder `ProvenanceGraph`
- Accept: `pnpm turbo run lint typecheck test build` and `pnpm schema:check`
- Demo-able: live fake poisoned-bill stream at `/x-ray`.

## P1 Core

- Packages: `packages/core`
- [ ] Monitor `decide()` with the 6-step order ([architecture.md](architecture.md#monitor-decision-order)); reason codes enumerated in the model
- [ ] Ledger (writes only via user-authored / user-endorsed), contract monotonicity
- [ ] Audit hash chain + `verify_chain`
- [ ] Oracle predicates for I1-I6 (attacker-goal and user-goal)
- [ ] Unit tests citing I/A IDs; Hypothesis fuzz harness asserting I1-I5 after every step
- Accept: `cd packages/core && uv run pytest`; `pnpm schema:check` after any model change
- Demo-able: nothing visual; fuzz result is the artifact.

## P2 World + attacks + Hijacked Mode + CLI

- Packages: `packages/world`, `packages/cli`
- [ ] Seeded world (bank, inbox, calendar, files, Slack) with reset
- [ ] A1-A14 fixtures aligned to the [taxonomy](threat-model.md#attack-taxonomy-and-stops), each with expected verdict and deciding step
- [ ] Hijacked Mode runner (raw tool calls, no LLM)
- [ ] `notary replay`, `notary fuzz`, `notary attack` implemented (`bench` may stay stubbed)
- Accept: `cd packages/world && uv run pytest`; `uv run notary attack --list` prints A1-A14; `uv run notary fuzz` reports zero violations
- Demo-able: full attack run from the terminal, no UI, no LLM.

## P3 Gateway, Value Store, Compiler, Runner, event stream

- Packages: `packages/mcp-proxy`, `packages/core`, `apps/server`
- [ ] Tool Gateway with hash pinning and labeled field splitting
- [ ] Value Store; Intent Compiler; Quarantined Extractor (optional)
- [ ] Agent runner on the Anthropic SDK, hand-written tool loop, record/replay cassettes keyed by prompt hash
- [ ] Server streams real events (replaces the hard-coded run)
- Accept: `pnpm turbo run test`; replay of a cassette twice yields byte-identical event streams
- Demo-able: poisoned-bill run end to end, still read through the existing `/x-ray` stream.

## P4 Trust X-ray UI

- Packages: `packages/ui`, `apps/web`, `packages/client`
- [ ] Contract panel, real provenance graph, decision stream, oracle lights
- [ ] Endorsement card; three-lane view
- Accept: `cd apps/web && pnpm test`; `pnpm turbo run build`
- Demo-able: stage script steps 1-4 ([demo.md](demo.md#three-minute-stage-script)).

## P5 Judge playground

- Packages: `apps/web`, `apps/server`, `packages/ui`
- [ ] Four modes: Poison the world, Be the hijacked LLM, Attack library, Attacker arena
- [ ] Replay scrubber
- Accept: each mode has a test driving it against the seeded world; oracle verdicts match expected
- Demo-able: step 5 (Hijacked Mode with a judge).

## P6 MCP proxy and evals

- Packages: `packages/mcp-proxy`, `packages/eval`
- [ ] MCP proxy in front of a real MCP server
- [ ] AgentDojo banking and Slack runs (if allowed); results export JSON -> charts
- [ ] Slide deck numbers updated from the export
- Accept: `uv run` eval entry point writes results consumed by the charts; metrics per bucket as in [threat-model.md](threat-model.md#metrics)
- Demo-able: step 6 numbers; optional proxy clip.

## P7 Hardening and demo prep

- Packages: all
- [ ] Deterministic stage run; offline fallback; public deploy
- [ ] Two full rehearsals; final deck update
- Accept: [pre-demo checklist](demo.md#pre-demo-checklist) fully checked
- Demo-able: everything.

## Risks

| Risk                                   | Mitigation                                                                                                  |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Schema drift between Python and TS     | `pnpm schema:check` in CI; generated files never hand-edited                                                |
| LLM nondeterminism in the demo         | cassette replay for the stage run; live mode labeled and temperature 0                                      |
| Label / sensitive-parameter table gaps | the table is the trusted base ([limitations](threat-model.md#honest-limitations)): hand-review plus fuzzing |
| Running out of time                    | cut line above                                                                                              |
| Venue connectivity                     | offline `docker compose up`, recorded run, screenshots                                                      |
