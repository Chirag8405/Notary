# Build phases

Ordered by dependency, not calendar; built by 4 people in parallel behind frozen contracts. Components and IDs: [architecture.md](architecture.md). Attacks, invariants, test coverage: [threat-model.md](threat-model.md). Demo surfaces: [demo.md](demo.md).

## Phases and dependencies

"Needs" is what a phase must have to start: contracts only (frozen in P0b), never another phase's implementation. "Integrates with" is the real implementation it plugs into later, at a [checkpoint](#integration-checkpoints).

| Phase | Goal                                                                                       | Lane           | Needs (contracts only)                              | Integrates with (real implementation) | Status      |
| ----- | ------------------------------------------------------------------------------------------ | -------------- | --------------------------------------------------- | ------------------------------------- | ----------- |
| P0    | Foundations                                                                                | all            | -                                                   | -                                     | done        |
| P0b   | Contract freeze + stubs                                                                    | all (A drafts) | P0                                                  | -                                     | done        |
| P1    | Core: monitor, ledger, audit chain, parameter table                                        | A              | P0b                                                 | P2 (CP1), P3a, P3b (CP2)              | done        |
| P2    | World, attacks, oracle, fuzz, Hijacked Mode, `ClassifierFilter`, CLI                       | B              | P0b (`FakeMonitor`, fixture and cassette formats)   | P1 (CP1)                              | done        |
| P3a   | Deterministic pipeline: pure Gateway logic, Value Store, gateway I/O adapter, Output Guard | A              | P0b (Gateway/Value Store interfaces), P1 models     | P1 monitor, P3b (CP2)                 | done        |
| P3b   | LLM side: compiler, runner, cassettes, Undefended baseline                                 | C              | P0b (`FakeMonitor`, `FakeGateway`, cassette format) | P1, P3a (CP2)                         | done        |
| P3c   | Server event stream + playground endpoints                                                 | C              | P0b (Event union, command messages, golden streams) | P3b, P3a (CP2)                        | done        |
| P3d   | Endorsement backend                                                                        | C              | P0b (command messages), P1 models                   | P1, P3c (CP3)                         | done        |
| P4    | Trust X-ray UI                                                                             | D              | P0b (golden streams, generated Zod)                 | P3c, P3d (CP3)                        | CP3 pending |
| P5    | Judge playground                                                                           | D              | P0b, P4 components                                  | P2 Hijacked Mode, P3c endpoints (CP4) | not started |
| P6    | MCP proxy (A), evals (B)                                                                   | A, B           | P0b (eval harness plumbing)                         | P3a, P3b, P1 (CP4)                    | not started |
| P7    | Hardening and demo prep                                                                    | all            | CP1-CP4                                             | everything                            | not started |

Start immediately after P0b, in parallel: P1, P2 (fixtures, oracle, fuzz harness and CLI against `FakeMonitor`), P3b, P3c, P3d (against contracts), P4 (against golden streams), P6 eval harness plumbing. Only the integration checkpoints and P7 are true blockers.

**Critical path:** the monitor (P1) is the only critical-path item for correctness. Everything else runs in parallel behind the frozen contracts and rejoins at the checkpoints below.

**Cut line** (drop first, in order): attacker arena (P5) -> Output Guard polish (P3a, first thing cut) and Quarantined Extractor (P3b) -> replay scrubber (P5) -> AgentDojo suites beyond banking (P6) -> MCP proxy clip (P6) -> second non-Claude model (P7). Never cut: monitor, fuzz harness, Hijacked Mode, X-ray decision stream, oracle lights, baseline lanes (stage-script steps 1-2 depend on them).

## Workstreams

Names TBD. Directory ownership: one owner approves changes to their packages (lane A approves anything under `packages/core` and `packages/mcp-proxy`, including logic written by other lanes; lane C consumes `packages/mcp-proxy`). Cross-lane changes go through the contract-change rule in [P0b](#p0b-contract-freeze--stubs).

| Lane | Owner | Packages                                          | Order                                                                                                                                                                                                                                                           |
| ---- | ----- | ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A    | TBD   | `packages/core`, `packages/mcp-proxy`             | P1 -> P3a: monitor, sensitive-parameter table, ledger, audit chain, then pure Gateway logic, Value Store, gateway I/O adapter, Output Guard -> P6 MCP proxy -> tail: public deploy, offline `docker compose up` fallback, recorded-run and screenshots fallback |
| B    | TBD   | `packages/world`, `packages/cli`, `packages/eval` | P2 -> P6 eval: seeded world, A1-A14 fixtures, oracle (I1-I6), Hypothesis fuzz harness, Hijacked Mode, Classifier-only baseline, CLI, then AgentDojo harness                                                                                                     |
| C    | TBD   | `apps/server` (consumes `packages/mcp-proxy`)     | P3b (incl. Undefended baseline) -> P3c (incl. playground endpoints) -> P3d                                                                                                                                                                                      |
| D    | TBD   | `packages/ui`, `apps/web`, `packages/client`      | P4 -> P5 (consumes lane C's playground endpoints), then demo script and deck updates                                                                                                                                                                            |

## Integration checkpoints

| CP  | Lanes     | Demonstrates                                                                                                                                            | Proof                                                                                     |
| --- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| CP1 | A + B     | real monitor passes all A1-A14 fixtures; `notary fuzz` reports zero violations; no LLM, no UI. Plan one contract revision window here                   | `cd packages/world && uv run pytest`; `uv run notary fuzz`; `uv run notary attack`        |
| CP2 | C + A     | runner replays the poisoned bill through the real monitor and Gateway, producing the event stream                                                       | `cd apps/server && uv run pytest tests/test_cp2.py` (cassette replay, no network): byte-identical streams, A3 not paid |
| CP3 | D + C + B | UI renders that live stream, including the endorsement flow (P3d) and the Classifier-only lane (P2); stage-script steps 1-4 work in the three-lane view | `pnpm dev`, open `/x-ray`; [stage script](demo.md#three-minute-stage-script) steps 1-4; golden proof automated (`apps/web/tests/cp3.test.tsx`); cassette proof: automated stream checks and the manual walk-through, recorded in PR #199 |
| CP4 | all       | playground modes working and eval numbers in the deck                                                                                                   | each playground mode runs against the seeded world; eval export matches the slides        |

## P0 Foundations (done)

- Packages: all; no business logic.
- [x] Turborepo + pnpm + uv workspace; Pydantic -> JSON Schema -> TS types + Zod; drift check; boundaries and import-linter; Docker Compose; CI
- [x] `/x-ray` vertical slice: hard-coded typed event stream -> client -> `DecisionStream` + placeholder `ProvenanceGraph`
- Accept: `pnpm turbo run lint typecheck test build` and `pnpm schema:check`
- Demo-able: live fake poisoned-bill stream at `/x-ray`.

## P0b Contract freeze + stubs

- Packages: `packages/core`, `packages/world`
- Freeze and tag these contracts:
  - [x] `decide()` signature
  - [x] Event union (server -> client), with a `lane` field (`undefended` | `classifier` | `notary`) and a run id on every event
  - [x] Intent Contract and value labels carried in events (`run_started`, `value_labeled`), so UI panels need no other source
  - [x] Client -> server command messages: endorsement approve/reject, Hijacked Mode raw tool call, Poison-the-world config, attacker-arena start
  - [x] Pure Gateway and Value Store interfaces: label the fields of a tool result into value refs; store/lookup API
  - [x] `AgentRunner` interface with two hook points: (a) a pre-filter applied to tool results before the agent sees them; (b) the Gateway/monitor hook. Lanes are configurations of one runner: Undefended = no hooks; Classifier-only = `ClassifierFilter` (supplied by lane B); NOTARY = Gateway + monitor
  - [x] Attack-case and fixture format; cassette format, with the lane as part of the cassette key (each lane has its own recordings)
- [x] `FakeMonitor` returning each fixture's expected verdict; test-support only, lives in `packages/world`, never imported by `core`
- [x] `FakeGateway` stub (test-support, lives in `packages/world`, never imported by `core`)
- [x] Name the classifier used for the Classifier-only baseline; document it in `docs/demo.md` and here. If a stand-in, label it in the UI
- [x] 3-4 golden event streams as JSON in `packages/world`: poisoned-bill run for A3, one legitimate-bill run, plus one or two more; all three lanes covered
- [ ] Ownership map: owners filled in the [Workstreams](#workstreams) table (names needed)
- Process: one named owner (lane A) drafts the freeze; others review within a fixed window (TBD). Plan one revision window at CP1.
- Accept: stubs pass typecheck; golden streams include all three lanes and validate against the generated Zod schema; command messages have Pydantic models and generated Zod; `pnpm schema:check` clean
- Tag: `contracts-v1` (annotated git tag on the P0b commit). Frozen in `packages/core/src/notary_core/` (`models/`, `monitor.py`, `gateway.py`, `runner.py`) and `packages/world/src/notary_world/` (`models.py`, `cassette.py`, `fakes.py`, `golden.py`).
- Classifier for the Classifier-only baseline: a **stand-in** heuristic injection filter (regex/keyword rules, not a trained classifier), reported as `RunStarted.classifier` and labeled "stand-in" in the UI. Swap in a real classifier later behind the same `ResultPreFilter` hook. See [demo.md](demo.md#trust-x-ray-appsweb-route-x-ray-components-in-packagesui).
- Rule: after the freeze, any contract change needs a one-line announcement in the team channel and a green `schema:check` in the same PR.
- Demo-able: nothing new; unblocks all lanes.

## P1 Core (lane A)

- Packages: `packages/core`
- [x] Monitor `decide()` with the 6-step order ([architecture.md](architecture.md#monitor-decision-order)); reason codes enumerated in the model
- [x] Sensitive-parameter table and offline floor defaults (the trusted base)
- [x] Review: two people review the sensitive-parameter table
- [x] Ledger (writes only via user-authored / user-endorsed), contract monotonicity
- [x] Audit hash chain + `verify_chain`
- [x] Unit tests citing I/A IDs
- Accept: `cd packages/core && uv run pytest`; `pnpm schema:check` after any model change
- Demo-able: nothing visual; unit tests pass. The fuzz result (P2, CP1) is the proof artifact.

## P2 World + attacks + oracle + fuzz + Hijacked Mode + Classifier-only baseline + CLI (lane B)

- Packages: `packages/world`, `packages/cli`
- [x] Seeded world (bank, inbox, calendar, files, Slack) with reset
- [x] A1-A14 fixtures aligned to the [taxonomy](threat-model.md#attack-taxonomy-and-stops), each with expected verdict and deciding step; runs against the real monitor (`FakeMonitor` only unit-tests the harness)
- [x] Oracle in `packages/world`: I1-I6 plus attacker-goal and user-goal predicates; it diffs world state, `core` stays pure and only holds the `OracleResult` model
  - Readers use the encoding decided in #40 (`"*"` = public, `()` = nobody, join = intersection; always normalized via `normalize_readers` in `notary_core.provenance`); integrity order is untrusted < endorsed < trusted, and `endorsed` never admits a guarded value by label alone (see [decisions.md](decisions.md)).
- [x] Hypothesis fuzz harness asserting I1-I5 after every step (runs against the real monitor; `FakeMonitor` is not used)
- [x] Hijacked Mode runner (raw tool calls, no LLM)
- [x] **Classifier-only** baseline: lane B owns the `ClassifierFilter` (a pure function from content to filtered content plus flags; classifier: see P0b) and its eval wrapper. It plugs into lane C's runner through the frozen pre-filter hook and needs no agent loop of its own
- [x] `notary replay`, `notary fuzz`, `notary attack` implemented (`bench` may stay stubbed)
- Accept: `cd packages/world && uv run pytest`; `uv run notary attack --list` prints A1-A14; after CP1, `uv run notary fuzz` reports zero violations
- Accept (baseline): `ClassifierFilter` has unit tests; the Classifier-only lane reproduces the swapped-IBAN loss once plugged into the P3b runner (CP2)
- Demo-able: full attack run from the terminal, no UI, no LLM; stage-script step 2 once the filter is plugged into the runner.

**P3 status (CP2, #142).** All P3 leaves are merged, including the optional Output Guard, Quarantined Extractor and attacker arena (none were cut). The committed cassettes are **scripted** (`"model": "scripted-v1"`): real prompt-hash keys, responses written by `notary_server.recording`. Live mode runs on Groq (`GROQ_API_KEY`, `openai/gpt-oss-120b`). A first real recording was made and does not yet match the scripted behaviour (findings in #182), so the scripted cassettes stay committed. The I3 order gap in `check_i3` (#183) is fixed: a message is compared only with secrets stored before it was sent.

## P3a Deterministic pipeline (lane A)

- Packages: `packages/core` (pure logic only), `packages/mcp-proxy` (I/O adapter; see [decisions.md](decisions.md))
- [x] Gateway: pure labeling and field-splitting logic
- [x] Value Store
  - Readers use the encoding decided in #40 (`"*"` = public, `()` = nobody, join = intersection; always normalized via `normalize_readers` in `notary_core.provenance`); integrity order is untrusted < endorsed < trusted, and `endorsed` never admits a guarded value by label alone (see [decisions.md](decisions.md)).
- [x] Gateway I/O adapter in `packages/mcp-proxy` (calls the pure logic in `core`), after the pure logic; lane C consumes it
- [x] Output Guard (A13); pure sentence-provenance logic in `core`. Last: after CP2; not needed for stage-script steps 1-5; first thing cut
- Needs P0b interfaces and P1 models.
- Accept: unit tests citing I/A IDs; a test that no value reaches the monitor unlabeled; a gateway test proving no effect occurs outside the adapter (I1)
- Demo-able: terminal-level poisoned-bill run through the real Gateway and monitor.

## P3b LLM side (lane C)

- Packages: `apps/server`
- [x] Intent Compiler
- [x] Quarantined Extractor (optional)
- [x] Agent runner on the Groq SDK, hand-written tool loop; implements the `AgentRunner` hooks (pre-filter, Gateway/monitor) so all three lanes run on it; tool calls go through the P3a adapter once it lands
- [x] Cassette record/replay keyed by prompt hash
- [x] **Undefended** baseline agent (the Classifier-only baseline is in P2)
- Needs P0b only (incl. `FakeMonitor`, `FakeGateway`, `AgentRunner` hooks); uses the fakes until P1 and P3a land.
- Accept: cassette replay twice gives byte-identical event streams; the Undefended lane reproduces the swapped-IBAN loss
- Demo-able: stage-script step 1.

## P3c Server event stream + playground endpoints (lane C)

- Packages: `apps/server`
- [x] FastAPI endpoints and WebSocket replace the hard-coded run
- [x] Playground endpoints for P5, built on the P0b command messages: Poison-the-world config, Hijacked Mode raw tool call, attacker-arena start, attack-library trigger; lane D consumes them
- Needs P0b only.
- Accept: golden stream served identically over WebSocket and validated by the client (`cd apps/server && uv run pytest`; `cd packages/client && pnpm test`); each command message round-trips Pydantic -> Zod
- Demo-able: golden stream at `/x-ray`.

## P3d Endorsement backend (lane C)

- Packages: `apps/server`; pure label logic (diff card from labels) stays in `packages/core` and is approved by lane A
- [x] Endorsement Service backend: diff card built from labels, per-session approval budget, ledger write on approval, approve/reject commands
- Needs P0b command messages and P1 models.
- Accept: unit tests citing I/A IDs (I4: ledger changes only via user-authored or user-endorsed writes); approval budget exhaustion turns ESCALATE into BLOCK
- Demo-able: endorsement card flow in stage-script step 3 at CP3.

## P4 Trust X-ray UI (lane D)

- Packages: `packages/ui`, `apps/web`, `packages/client`
- [x] Contract panel, real provenance graph, decision stream, oracle lights (#164, #165, #166, #167, #168)
- [x] Endorsement card; three-lane view (#170, #171)
- [x] RunView, client lane/mode/send, content inspector (#162, #163, #169)
- [x] `/x-ray` page: regions, run controls, effects list, audit anchor footer, mode handling (#172, #191)
- [ ] CP3 manual walk-through of stage-script steps 1-4 on the cassette stack (maintainer; PR #199)
- Built against golden streams until CP3. Endorsement card uses the P0b approve/reject commands.
- Accept: `cd apps/web && pnpm test`; `pnpm turbo run build`
- Demo-able: stage script steps 1-4 ([demo.md](demo.md#three-minute-stage-script)) at CP3.
- CP3 status: the golden proof is automated (`apps/web/tests/cp3.test.tsx`); the cassette proof is the automated stream checks plus the manual walk-through recorded in PR #199. CP2 is not touched here.
- Open follow-ups: #193 golden mode ignores the lane (fixed), #194 a closing golden socket cancels a pending cassette card, #195 the pending list is empty right after `endorsement_requested`, #196 `legitimate_bill` has no golden stream, #197 the React Flow attribution is hidden, #198 confirming the card pays the attacker.

## P5 Judge playground (lane D)

- Packages: `apps/web`, `packages/ui`, `packages/client` (endpoints come from lane C, P3c)
- [ ] Four modes: Poison the world, Be the hijacked LLM, Attack library, Attacker arena
- [ ] Replay scrubber
- Accept: each mode has a test driving it against the seeded world; oracle verdicts match expected
- Demo-able: step 5 (Hijacked Mode with a judge).

## P6 MCP proxy and evals (lanes A, B)

- Packages: `packages/mcp-proxy` (lane A), `packages/eval` (lane B)
- [ ] Eval harness plumbing (result shapes, export, charts) against stubs (lane B)
- [ ] MCP proxy in front of a real MCP server (lane A)
- [ ] AgentDojo banking and Slack runs (if allowed); results export JSON -> charts (lane B)
- [ ] Slide deck numbers updated from the export
- Accept: `uv run` eval entry point writes results consumed by the charts; metrics per bucket as in [threat-model.md](threat-model.md#metrics)
- Demo-able: step 6 numbers; optional proxy clip.

## P7 Hardening and demo prep

- Packages: all
- Needs CP1-CP4.
- Shared:
  - [ ] Deterministic stage run
  - [ ] Final deck update
  - [ ] Two full rehearsals
- Lane A (after P3a):
  - [ ] Public deploy
  - [ ] Offline `docker compose up` fallback
  - [ ] Recorded-run and screenshots fallback
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
