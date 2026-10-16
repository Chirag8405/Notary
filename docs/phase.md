# Build phases

Ordered by dependency, not calendar; built by 4 people in parallel behind frozen contracts. Components and IDs: [architecture.md](architecture.md). Attacks, invariants, test coverage: [threat-model.md](threat-model.md). Demo surfaces: [demo.md](demo.md).

## Phases and dependencies

"Needs" is what a phase must have to start: contracts only (frozen in P0b), never another phase's implementation. "Integrates with" is the real implementation it plugs into later, at a [checkpoint](#integration-checkpoints).

| Phase | Goal                                                                       | Lane           | Needs (contracts only)                              | Integrates with (real implementation) | Date | Status            |
| ----- | -------------------------------------------------------------------------- | -------------- | --------------------------------------------------- | ------------------------------------- | ---- | ----------------- |
| P0    | Foundations                                                                | all            | -                                                   | -                                     | TBD  | done              |
| P0b   | Contract freeze + stubs                                                    | all (A drafts) | P0                                                  | -                                     | TBD  | next (first hour) |
| P1    | Core: monitor, ledger, audit chain, parameter table                        | A              | P0b                                                 | P2 (CP1), P3a, P3b (CP2)              | TBD  | after P0b         |
| P2    | World, attacks, oracle, fuzz, Hijacked Mode, CLI                           | B              | P0b (`FakeMonitor`, fixture format)                 | P1 (CP1)                              | TBD  | not started       |
| P3a   | Deterministic pipeline: pure Gateway logic, Value Store                    | A              | P0b, P1 models                                      | P1 monitor, P3b (CP2)                 | TBD  | not started       |
| P3b   | LLM side: compiler, runner, cassettes, baseline lanes, gateway I/O adapter | C              | P0b (`FakeMonitor`, cassette format)                | P1, P3a (CP2)                         | TBD  | not started       |
| P3c   | Server event stream + playground endpoints                                 | C              | P0b (Event union, command messages, golden streams) | P3b, P3a (CP2)                        | TBD  | not started       |
| P3d   | Endorsement backend + Output Guard                                         | C              | P0b (command messages), P1 models                   | P1, P3a, P3c (CP3)                    | TBD  | not started       |
| P4    | Trust X-ray UI                                                             | D              | P0b (golden streams, generated Zod)                 | P3c, P3d (CP3)                        | TBD  | not started       |
| P5    | Judge playground                                                           | D              | P0b, P4 components                                  | P2 Hijacked Mode, P3c endpoints (CP4) | TBD  | not started       |
| P6    | MCP proxy, evals                                                           | B, C           | P0b (eval harness plumbing)                         | P3a, P3b, P1 (CP4)                    | TBD  | not started       |
| P7    | Hardening and demo prep                                                    | all            | CP1-CP4                                             | everything                            | TBD  | not started       |

Start immediately after P0b, in parallel: P1, P2 (fixtures, oracle, fuzz harness and CLI against `FakeMonitor`), P3b, P3c, P3d (against contracts), P4 (against golden streams), P6 eval harness plumbing. Only the integration checkpoints and P7 are true blockers.

**Critical path:** the monitor (P1) is the only critical-path item for correctness. Everything else runs in parallel behind the frozen contracts and rejoins at the checkpoints below.

**Cut line** (drop first, in order): attacker arena (P5) -> Output Guard polish and Quarantined Extractor (P3d, P3b) -> replay scrubber (P5) -> AgentDojo suites beyond banking (P6) -> MCP proxy clip (P6) -> second non-Claude model (P7). Never cut: monitor, fuzz harness, Hijacked Mode, X-ray decision stream, oracle lights, baseline lanes (stage-script steps 1-2 depend on them).

## Workstreams

Names TBD. Directory ownership: one owner approves changes to their packages (lane A approves anything under `packages/core`, including pure logic written by other lanes). Cross-lane changes go through the contract-change rule in [P0b](#p0b-contract-freeze--stubs).

| Lane | Owner | Packages                                                        | Order                                                                                                                             |
| ---- | ----- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| A    | TBD   | `packages/core` (incl. pure gateway logic)                      | P1 -> P3a: monitor, sensitive-parameter table, ledger, audit chain, then pure Gateway logic and Value Store                       |
| B    | TBD   | `packages/world`, `packages/cli`, `packages/eval`               | P2 -> P6 eval: seeded world, A1-A14 fixtures, oracle (I1-I6), Hypothesis fuzz harness, Hijacked Mode, CLI, then AgentDojo harness |
| C    | TBD   | `apps/server`, `packages/mcp-proxy` (incl. gateway I/O adapter) | P3b -> P3c (incl. playground endpoints) -> P3d -> MCP proxy                                                                       |
| D    | TBD   | `packages/ui`, `apps/web`, `packages/client`                    | P4 -> P5 (consumes lane C's playground endpoints), then demo script, deck updates, deploy                                         |

## Integration checkpoints

| CP  | Lanes | Demonstrates                                                                                                                          | Proof                                                                                     |
| --- | ----- | ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| CP1 | A + B | real monitor passes all A1-A14 fixtures; `notary fuzz` reports zero violations; no LLM, no UI. Plan one contract revision window here | `cd packages/world && uv run pytest`; `uv run notary fuzz`; `uv run notary attack`        |
| CP2 | C + A | runner replays the poisoned bill through the real monitor and Gateway, producing the event stream                                     | cassette replay test in `apps/server/tests` (planned): byte-identical streams, A3 blocked |
| CP3 | D + C | UI renders that live stream, including the endorsement flow (P3d); stage-script steps 1-4 work in the three-lane view                 | `pnpm dev`, open `/x-ray`; [stage script](demo.md#three-minute-stage-script) steps 1-4    |
| CP4 | all   | playground modes working and eval numbers in the deck                                                                                 | each playground mode runs against the seeded world; eval export matches the slides        |

## P0 Foundations (done)

- Packages: all; no business logic.
- [x] Turborepo + pnpm + uv workspace; Pydantic -> JSON Schema -> TS types + Zod; drift check; boundaries and import-linter; Docker Compose; CI
- [x] `/x-ray` vertical slice: hard-coded typed event stream -> client -> `DecisionStream` + placeholder `ProvenanceGraph`
- Accept: `pnpm turbo run lint typecheck test build` and `pnpm schema:check`
- Demo-able: live fake poisoned-bill stream at `/x-ray`.

## P0b Contract freeze + stubs

- Packages: `packages/core`, `packages/world`
- Freeze and tag these contracts:
  - [ ] `decide()` signature
  - [ ] Event union (server -> client), with a `lane` field (`undefended` | `classifier` | `notary`) and a run id on every event
  - [ ] Intent Contract and value labels carried in events (`run_started`, `value_labeled`), so UI panels need no other source
  - [ ] Client -> server command messages: endorsement approve/reject, Hijacked Mode raw tool call, Poison-the-world config, attacker-arena start
  - [ ] Attack-case and fixture format; cassette format
- [ ] `FakeMonitor` returning each fixture's expected verdict; test-support only, lives in `packages/world`, never imported by `core`
- [ ] 3-4 golden event streams as JSON in `packages/world`: poisoned-bill run for A3, one legitimate-bill run, plus one or two more; all three lanes covered
- [ ] Ownership map: owners filled in the [Workstreams](#workstreams) table
- Process: one named owner (lane A) drafts the freeze; others review within a fixed window (TBD). Plan one revision window at CP1.
- Accept: stubs pass typecheck; golden streams include all three lanes and validate against the generated Zod schema; command messages have Pydantic models and generated Zod; `pnpm schema:check` clean
- Rule: after the freeze, any contract change needs a one-line announcement in the team channel and a green `schema:check` in the same PR.
- Demo-able: nothing new; unblocks all lanes.

## P1 Core (lane A)

- Packages: `packages/core`
- [ ] Monitor `decide()` with the 6-step order ([architecture.md](architecture.md#monitor-decision-order)); reason codes enumerated in the model
- [ ] Sensitive-parameter table and offline floor defaults (the trusted base)
- [ ] Review: two people review the sensitive-parameter table
- [ ] Ledger (writes only via user-authored / user-endorsed), contract monotonicity
- [ ] Audit hash chain + `verify_chain`
- [ ] Unit tests citing I/A IDs
- Accept: `cd packages/core && uv run pytest`; `pnpm schema:check` after any model change
- Demo-able: nothing visual; unit tests pass. The fuzz result (P2, CP1) is the proof artifact.

## P2 World + attacks + Hijacked Mode + CLI (lane B)

- Packages: `packages/world`, `packages/cli`
- [ ] Seeded world (bank, inbox, calendar, files, Slack) with reset
- [ ] A1-A14 fixtures aligned to the [taxonomy](threat-model.md#attack-taxonomy-and-stops), each with expected verdict and deciding step; runs against `FakeMonitor` until CP1
- [ ] Oracle in `packages/world`: I1-I6 plus attacker-goal and user-goal predicates; it diffs world state, `core` stays pure and only holds the `OracleResult` model
- [ ] Hypothesis fuzz harness asserting I1-I5 after every step (runs against `FakeMonitor` until CP1)
- [ ] Hijacked Mode runner (raw tool calls, no LLM)
- [ ] `notary replay`, `notary fuzz`, `notary attack` implemented (`bench` may stay stubbed)
- Accept: `cd packages/world && uv run pytest`; `uv run notary attack --list` prints A1-A14; after CP1, `uv run notary fuzz` reports zero violations
- Demo-able: full attack run from the terminal, no UI, no LLM.

## P3a Deterministic pipeline (lane A)

- Packages: `packages/core` (pure logic only; I/O stays outside, see [decisions.md](decisions.md))
- [ ] Gateway: pure labeling and field-splitting logic
- [ ] Value Store
- Needs P1 models only.
- Accept: unit tests citing I/A IDs; a test of the pure gateway logic that no value reaches the monitor unlabeled (I1 end to end is proven at CP2 with the adapter)
- Demo-able: terminal-level poisoned-bill run through the real Gateway logic and monitor.

## P3b LLM side (lane C)

- Packages: `apps/server`, `packages/mcp-proxy`
- [ ] Gateway I/O adapter in `packages/mcp-proxy` (calls the pure logic in `core`; lane C owns it)
- [ ] Intent Compiler
- [ ] Quarantined Extractor (optional)
- [ ] Agent runner on the Anthropic SDK, hand-written tool loop
- [ ] Cassette record/replay keyed by prompt hash
- [ ] Baseline lanes for the three-lane view and stage-script steps 1-2: **Undefended** agent and **Classifier-only** agent. Classifier: TBD; if a stand-in is used, say so here and label it in the UI
- Needs P0b only; uses `FakeMonitor` until P1 and P3a land.
- Accept: cassette replay twice gives byte-identical event streams; both baseline lanes reproduce the swapped-IBAN loss; a gateway test proving no effect occurs outside the adapter (I1)
- Demo-able: stage-script steps 1-2.

## P3c Server event stream + playground endpoints (lane C)

- Packages: `apps/server`
- [ ] FastAPI endpoints and WebSocket replace the hard-coded run
- [ ] Playground endpoints for P5, built on the P0b command messages: Poison-the-world config, Hijacked Mode raw tool call, attacker-arena start, attack-library trigger; lane D consumes them
- Needs P0b only.
- Accept: golden stream served identically over WebSocket and validated by the client (`cd apps/server && uv run pytest`; `cd packages/client && pnpm test`); each command message round-trips Pydantic -> Zod
- Demo-able: golden stream at `/x-ray`.

## P3d Endorsement backend + Output Guard (lane C)

- Packages: `apps/server`; pure label logic (diff card from labels, sentence provenance labels) stays in `packages/core` and is approved by lane A
- [ ] Endorsement Service backend: diff card built from labels, per-session approval budget, ledger write on approval, approve/reject commands
- [ ] Output Guard (A13)
- Needs P0b command messages and P1 models.
- Accept: unit tests citing I/A IDs (I4: ledger changes only via user-authored or user-endorsed writes); approval budget exhaustion turns ESCALATE into BLOCK
- Demo-able: endorsement card flow in stage-script step 3 at CP3.

## P4 Trust X-ray UI (lane D)

- Packages: `packages/ui`, `apps/web`, `packages/client`
- [ ] Contract panel, real provenance graph, decision stream, oracle lights
- [ ] Endorsement card; three-lane view
- Built against golden streams until CP3. Endorsement card uses the P0b approve/reject commands.
- Accept: `cd apps/web && pnpm test`; `pnpm turbo run build`
- Demo-able: stage script steps 1-4 ([demo.md](demo.md#three-minute-stage-script)) at CP3.

## P5 Judge playground (lane D)

- Packages: `apps/web`, `packages/ui`, `packages/client` (endpoints come from lane C, P3c)
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
- Needs CP1-CP4.
- [ ] Deterministic stage run; offline fallback; public deploy
- [ ] Final deck update
- [ ] Two full rehearsals
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
