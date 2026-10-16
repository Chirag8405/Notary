# Build phases

Ordered by dependency, not calendar; built by 4 people in parallel behind frozen contracts. Components and IDs: [architecture.md](architecture.md). Attacks, invariants, test coverage: [threat-model.md](threat-model.md). Demo surfaces: [demo.md](demo.md).

## Phases and dependencies

"Needs" is what a phase must have to start: contracts only (frozen in P0b), never another phase's implementation. "Integrates with" is the real implementation it plugs into later, at a [checkpoint](#integration-checkpoints).

| Phase | Goal                                                  | Lane | Needs (contracts only)               | Integrates with (real implementation) | Date | Status            |
| ----- | ----------------------------------------------------- | ---- | ------------------------------------ | ------------------------------------- | ---- | ----------------- |
| P0    | Foundations                                           | all  | -                                    | -                                     | TBD  | done              |
| P0b   | Contract freeze + stubs                               | all  | P0                                   | -                                     | TBD  | next (first hour) |
| P1    | Core                                                  | A    | P0b                                  | P2 (CP1), P3a, P3b (CP2)              | TBD  | next              |
| P2    | World, attacks, Hijacked Mode, CLI                    | B    | P0b (`FakeMonitor`, fixture format)  | P1 (CP1)                              | TBD  | not started       |
| P3a   | Deterministic pipeline                                | A    | P0b, P1 models                       | P1 monitor, P3b (CP2)                 | TBD  | not started       |
| P3b   | LLM side: compiler, runner, cassettes, baseline lanes | C    | P0b (`FakeMonitor`, cassette format) | P1, P3a (CP2)                         | TBD  | not started       |
| P3c   | Server event stream                                   | C    | P0b (Event union, golden streams)    | P3b, P3a (CP2)                        | TBD  | not started       |
| P4    | Trust X-ray UI                                        | D    | P0b (golden streams, generated Zod)  | P3c (CP3)                             | TBD  | not started       |
| P5    | Judge playground                                      | D    | P0b, P4 components                   | P2 Hijacked Mode, P3c (CP4)           | TBD  | not started       |
| P6    | MCP proxy, evals                                      | B, C | P0b (eval harness plumbing)          | P3a, P3b, P1 (CP4)                    | TBD  | not started       |
| P7    | Hardening and demo prep                               | all  | CP1-CP3                              | everything                            | TBD  | not started       |

Start immediately after P0b, in parallel: P1, P2 (fixtures and CLI against `FakeMonitor`), P3b, P3c, P4 (against golden streams), P6 eval harness plumbing. Only the integration checkpoints and P7 are true blockers.

**Critical path:** the monitor (P1) is the only critical-path item for correctness. Everything else runs in parallel behind the frozen contracts and rejoins at the checkpoints below.

**Cut line** (drop first, in order): attacker arena (P5) -> Output Guard polish and Quarantined Extractor (P3a, P3b) -> replay scrubber (P5) -> AgentDojo suites beyond banking (P6) -> MCP proxy clip (P6) -> second non-Claude model (P7). Never cut: monitor, fuzz harness, Hijacked Mode, X-ray decision stream, oracle lights, baseline lanes (stage-script steps 1-2 depend on them).

## Workstreams

Names TBD. Directory ownership: one owner approves changes to their packages. Cross-lane changes go through the contract-change rule in [P0b](#p0b-contract-freeze--stubs).

| Lane | Owner | Packages                                          | Order                                                                                                                                     |
| ---- | ----- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| A    | TBD   | `packages/core`, gateway adapter                  | P1 -> P3a: monitor, ledger, audit chain, oracle, sensitive-parameter table, fuzz, then Gateway / Value Store / Endorsement / Output Guard |
| B    | TBD   | `packages/world`, `packages/cli`, `packages/eval` | P2 -> P6 eval: seeded world, A1-A14 fixtures, Hijacked Mode, CLI, then AgentDojo harness                                                  |
| C    | TBD   | `apps/server`, `packages/mcp-proxy`               | P3b -> P3c -> MCP proxy                                                                                                                   |
| D    | TBD   | `packages/ui`, `apps/web`, `packages/client`      | P4 -> P5, then demo script, deck updates, deploy                                                                                          |

## Integration checkpoints

| CP  | Lanes | Demonstrates                                                                                      | Proof                                                                                                                   |
| --- | ----- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| CP1 | A + B | real monitor passes all A1-A14 fixtures; `notary fuzz` reports zero violations; no LLM, no UI     | `cd packages/world && uv run pytest`; `uv run notary fuzz`; `uv run notary attack`                                      |
| CP2 | C + A | runner replays the poisoned bill through the real monitor and Gateway, producing the event stream | cassette replay test in `apps/server/tests` (planned): byte-identical streams, A3 blocked                               |
| CP3 | D + C | UI renders that live stream; stage-script steps 1-4 work in the three-lane view                   | `pnpm dev`, open `/x-ray`; [stage script](demo.md#three-minute-stage-script) steps 1-4                                  |
| CP4 | all   | playground, eval numbers in the deck; then two rehearsals (P7)                                    | playground modes work on the seeded world; eval export matches slides; [pre-demo checklist](demo.md#pre-demo-checklist) |

## P0 Foundations (done)

- Packages: all; no business logic.
- [x] Turborepo + pnpm + uv workspace; Pydantic -> JSON Schema -> TS types + Zod; drift check; boundaries and import-linter; Docker Compose; CI
- [x] `/x-ray` vertical slice: hard-coded typed event stream -> client -> `DecisionStream` + placeholder `ProvenanceGraph`
- Accept: `pnpm turbo run lint typecheck test build` and `pnpm schema:check`
- Demo-able: live fake poisoned-bill stream at `/x-ray`.

## P0b Contract freeze + stubs

- Packages: `packages/core`, `packages/world`
- [ ] Freeze and tag the contracts: `decide()` signature, the Event union, attack-case and fixture format, cassette format
- [ ] `FakeMonitor` returning each fixture's expected verdict; test-support only, lives in `packages/world`, never imported by `core`
- [ ] 3-4 golden event streams as JSON in `packages/world`: poisoned-bill run for A3, one legitimate-bill run, plus one or two more
- [ ] Ownership map: owners filled in the [Workstreams](#workstreams) table
- Accept: stubs pass typecheck; golden streams validate against the generated Zod schema; `pnpm schema:check` clean
- Rule: after the freeze, any contract change needs a one-line announcement in the team channel and a green `schema:check` in the same PR.
- Demo-able: nothing new; unblocks all lanes.

## P1 Core (lane A)

- Packages: `packages/core`
- [ ] Monitor `decide()` with the 6-step order ([architecture.md](architecture.md#monitor-decision-order)); reason codes enumerated in the model
- [ ] Sensitive-parameter table and offline floor defaults (the trusted base)
- [ ] Review: two people review the sensitive-parameter table
- [ ] Ledger (writes only via user-authored / user-endorsed), contract monotonicity
- [ ] Audit hash chain + `verify_chain`
- [ ] Oracle predicates for I1-I6 (attacker-goal and user-goal)
- [ ] Unit tests citing I/A IDs; Hypothesis fuzz harness asserting I1-I5 after every step
- Accept: `cd packages/core && uv run pytest`; `pnpm schema:check` after any model change
- Demo-able: nothing visual; fuzz result is the artifact.

## P2 World + attacks + Hijacked Mode + CLI (lane B)

- Packages: `packages/world`, `packages/cli`
- [ ] Seeded world (bank, inbox, calendar, files, Slack) with reset
- [ ] A1-A14 fixtures aligned to the [taxonomy](threat-model.md#attack-taxonomy-and-stops), each with expected verdict and deciding step; runs against `FakeMonitor` until CP1
- [ ] Hijacked Mode runner (raw tool calls, no LLM)
- [ ] `notary replay`, `notary fuzz`, `notary attack` implemented (`bench` may stay stubbed)
- Accept: `cd packages/world && uv run pytest`; `uv run notary attack --list` prints A1-A14; after CP1, `uv run notary fuzz` reports zero violations
- Demo-able: full attack run from the terminal, no UI, no LLM.

## P3a Deterministic pipeline (lane A)

- Packages: `packages/core` (pure logic), `packages/mcp-proxy` or `apps/server` (I/O adapter; never in `core`; see [decisions.md](decisions.md))
- [ ] Gateway: pure labeling and field-splitting logic in `packages/core`; tool-calling I/O adapter outside core
- [ ] Value Store
- [ ] Endorsement Service backend: diff card built from labels, approval budget, ledger write on approval (persistence adapter outside core)
- [ ] Output Guard (A13)
- Needs P1 models only.
- Accept: unit tests citing I/A IDs; a gateway test proving no effect occurs outside it (I1)
- Demo-able: terminal-level poisoned-bill run through the real Gateway and monitor.

## P3b LLM side (lane C)

- Packages: `apps/server`
- [ ] Intent Compiler
- [ ] Quarantined Extractor (optional)
- [ ] Agent runner on the Anthropic SDK, hand-written tool loop
- [ ] Cassette record/replay keyed by prompt hash
- [ ] Baseline lanes for the three-lane view and stage-script steps 1-2: **Undefended** agent and **Classifier-only** agent. Classifier: TBD; if a stand-in is used, say so here and label it in the UI
- Needs P0b only; uses `FakeMonitor` until P1 and P3a land.
- Accept: cassette replay twice gives byte-identical event streams; both baseline lanes reproduce the swapped-IBAN loss
- Demo-able: stage-script steps 1-2.

## P3c Server event stream (lane C)

- Packages: `apps/server`
- [ ] FastAPI endpoints and WebSocket replace the hard-coded run
- Needs P0b only.
- Accept: golden stream served identically over WebSocket and validated by the client (`cd apps/server && uv run pytest`; `cd packages/client && pnpm test`)
- Demo-able: golden stream at `/x-ray`.

## P4 Trust X-ray UI (lane D)

- Packages: `packages/ui`, `apps/web`, `packages/client`
- [ ] Contract panel, real provenance graph, decision stream, oracle lights
- [ ] Endorsement card; three-lane view
- Built against golden streams until CP3.
- Accept: `cd apps/web && pnpm test`; `pnpm turbo run build`
- Demo-able: stage script steps 1-4 ([demo.md](demo.md#three-minute-stage-script)) at CP3.

## P5 Judge playground (lane D)

- Packages: `apps/web`, `apps/server`, `packages/ui`
- [ ] Four modes: Poison the world, Be the hijacked LLM, Attack library, Attacker arena
- [ ] Replay scrubber
- Accept: each mode has a test driving it against the seeded world; oracle verdicts match expected
- Demo-able: step 5 (Hijacked Mode with a judge).

## P6 MCP proxy and evals (lanes B, C)

- Packages: `packages/mcp-proxy`, `packages/eval`
- [ ] Eval harness plumbing (result shapes, export, charts) against stubs
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

| Risk                                          | Mitigation                                                                                                    |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Schema drift between Python and TS            | `pnpm schema:check` in CI; generated files never hand-edited                                                  |
| Lanes drift apart before integration          | frozen contracts, golden streams, integration checkpoints                                                     |
| Contract change mid-build breaks another lane | announcement rule plus `schema:check` in the same PR ([P0b](#p0b-contract-freeze--stubs))                     |
| LLM nondeterminism in the demo                | cassette replay for the stage run; live mode labeled and temperature 0                                        |
| Label / sensitive-parameter table gaps        | the table is the trusted base ([limitations](threat-model.md#honest-limitations)): two reviewers plus fuzzing |
| Running out of time                           | cut line above                                                                                                |
| Venue connectivity                            | offline `docker compose up`, recorded run, screenshots                                                        |
