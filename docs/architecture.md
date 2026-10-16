# Architecture

NOTARY assumes the agent's LLM is fully hijacked and shows that nothing the attacker wants can still happen. Security lives in a small deterministic reference monitor, never in prompts or classifiers. This doc owns components, the decision order and invariants (A/I IDs are defined in [threat-model.md](threat-model.md) and below). Status of each item is tracked in [phase.md](phase.md); rationale for tool choices is in [decisions.md](decisions.md).

Differentiators:

1. **Model-independent guarantee.** Hijacked Mode removes the LLM; a judge types raw tool calls and the monitor still holds (I6). See [demo.md](demo.md).
2. **Corroborated authority.** Untrusted content may supply values, but a value gains authority over a consequential action only when the user's trusted state corroborates it. "Pay this bill" keeps working.
3. **Visible mechanics.** The Trust X-ray shows each value's origin, each gate decision and the oracle's verdict.

## Trust boundaries

| Side                          | Contents                                                                                                                                                                                     |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Untrusted (attacker-writable) | email bodies and display names, files, web pages, calendar descriptions, Slack messages, every tool output, third-party tool descriptions, other agents' messages, anything the LLM produces |
| Trusted                       | the user's typed request, user-confirmed ledger entries, platform-stamped metadata (verified sender, account owner), the monitor and its policy                                              |

Attacker: writes any untrusted content, knows the design, iterates, fully controls LLM output. Cannot touch: the user's request, monitor code, the ledger's write path, platform-verified identities.

## Components

| Component                                  | Role                                                                                                                                                                                                                                                                                                                                                     | Repo path                                                                                                                                                                         | Status                                   |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| Tool Gateway                               | Only path to the world. Pins each tool's description+schema by hash at session start, rejects drift, splits results into structured fields stored as labeled values                                                                                                                                                                                      | pure labeling and field-splitting logic: `packages/core`; tool-calling I/O adapter: `packages/mcp-proxy` (`notary_mcp_proxy`)                                                     | stub (`Gateway`, `ToolPin` in mcp-proxy) |
| Value Store                                | Handle + label per value: origin, integrity, confidentiality (readers), pointer to source span. Derived values take the lowest integrity and narrowest readers of their inputs                                                                                                                                                                           | models in `packages/core` (`Label`, `ValueRef`); store itself planned                                                                                                             | models only                              |
| Intent Compiler (trusted)                  | Sees only the user request and tool schemas, never fetched content. Outputs a frozen Intent Contract: effect tools, marker per sensitive parameter (`literal`, `named_source`, `ledger`, `endorse`, `free`), effect budget, egress destinations, authorized irreversible actions. Offline per-parameter floor defaults cannot be relaxed by the compiler | `IntentContract` in `packages/core`; compiler planned                                                                                                                             | model only                               |
| Agent LLM (untrusted)                      | Reads content with spotlighting, plans freely, proposes tool calls. Read-only calls pass ungated. Guarded parameters resolve to stored values by decision unit (whole address, whole IBAN, URL host)                                                                                                                                                     | `apps/server` runner                                                                                                                                                              | replays a hard-coded run                 |
| Quarantined Extractor (optional, no tools) | Turns messy content into typed fields with span refs; gateway verifies each span exists, so fabricated values are unsourced                                                                                                                                                                                                                              | planned                                                                                                                                                                           | planned                                  |
| Reference Monitor                          | Deterministic, small, pure: `decide(call, contract, labels, ledger) -> ALLOW \| ESCALATE \| BLOCK` + reasons                                                                                                                                                                                                                                             | `packages/core/src/notary_core/monitor.py`                                                                                                                                        | stub (`NotImplementedError`)             |
| Trusted Ledger                             | Contacts, payees, past transactions, owned resources, verified senders. Grows only via user-typed or user-endorsed actions, never from tool results (I4)                                                                                                                                                                                                 | `LedgerEntry` in `packages/core`                                                                                                                                                  | model only                               |
| Endorsement Service                        | Turns ESCALATE into a diff card built from labels (not LLM prose). Per-session approval budget; past it escalations become blocks. Approved value is written to the ledger (trust on first use)                                                                                                                                                          | `Endorsement`, `DiffCard`, `DiffRow` in `packages/core`                                                                                                                           | models only                              |
| Output Guard                               | Labels final-answer sentences by provenance; untrusted URLs/phones/accounts shown quoted and attributed; links defanged unless in ledger; reports "this email asked me to do X; I did not"                                                                                                                                                               | planned                                                                                                                                                                           | planned                                  |
| Audit Log + Oracle                         | Append-only hash-chained log of every call, label, contract version, decision+reason. Oracle diffs environment state against attacker-goal and user-goal predicates, independent of agent claims                                                                                                                                                         | hash-chained audit log: `AuditEntry`, `verify_chain` (stub) in `packages/core`; oracle: `packages/world` (planned), `core` holds only the `OracleResult`/`InvariantResult` models | models + stub                            |

The agent runner is one `AgentRunner` with two hook points (a pre-filter on tool results, and the Gateway/monitor hook); the three lanes are configurations of it: Undefended = no hooks; Classifier-only = `ClassifierFilter` (lane B); NOTARY = Gateway + monitor. Frozen in [phase.md P0b](phase.md#p0b-contract-freeze--stubs).

`packages/core` imports only `pydantic` and the stdlib: no I/O, network, randomness, clock or LLM calls (enforced by `packages/core/tests/test_core_purity.py` and an import-linter contract).

```mermaid
flowchart LR
  U["User request"] --> IC["Intent Compiler"]
  IC --> C["Intent Contract (frozen)"]
  X["Untrusted content"] --> G["Tool Gateway"]
  G --> VS["Value Store"]
  A["Agent LLM"] -->|"proposed call"| M["Reference Monitor"]
  C --> M
  VS --> M
  L["Trusted Ledger"] --> M
  M -->|ALLOW| E["Tools / effects"]
  M -->|ESCALATE| ES["Endorsement Service"]
  ES --> UC["User"]
  UC -->|"approve"| L
  M -->|BLOCK| B["Blocked + reason"]
  E --> AL["Audit Log"]
  ES --> AL
  B --> AL
  G --> AL
  AL --> O["Oracle"]
  A -->|"final answer"| OG["Output Guard"]
  VS --> OG
```

Poisoned-bill flow (A3):

```mermaid
sequenceDiagram
  participant U as User
  participant IC as Intent Compiler
  participant A as Agent LLM
  participant G as Gateway
  participant M as Monitor
  participant L as Ledger
  participant O as Oracle
  U->>IC: "pay the bill in december.txt"
  IC-->>M: contract (pay_bill, payee: endorse, budget)
  A->>G: read december.txt
  G-->>A: fields labeled untrusted (IBAN from file)
  A->>M: pay_bill(payee = IBAN value)
  M->>L: exact / near match for IBAN?
  L-->>M: no exact match, near match to known payee
  M-->>U: BLOCK (lookalike) or ESCALATE (diff card)
  M->>O: decision + state
  O-->>U: attacker goal not reached
```

## Monitor decision order

Fixed. Code constant: `CHECK_ORDER` in `packages/core/src/notary_core/models/decision.py`; `Decision.reasons` follows it.

| #   | Step (code id)                          | Rule                                                                                                                                                                                              | Verdicts                                | Attacks         |
| --- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- | --------------- |
| 1   | Contract scope (`scope`)                | tool in contract AND manifest hash matches                                                                                                                                                        | else BLOCK                              | A1, A2, A4, A10 |
| 2   | Irreversibility (`irreversibility`)     | deletes, permission grants etc. need explicit authorization in the request                                                                                                                        | else BLOCK                              | A4              |
| 3   | Origin per guarded parameter (`origin`) | admit if value matches the request, a named verified source, or the ledger, as the marker allows                                                                                                  | else continue to 4 for untrusted values | A3, A6, A7      |
| 4   | Corroboration (`corroboration`)         | exact ledger match by decision unit -> ALLOW; near match after normalization (homoglyphs, case, edit distance) -> BLOCK as lookalike; no match and marker is `endorse` -> ESCALATE with diff card | ALLOW / BLOCK / ESCALATE                | A3, A8, A9      |
| 5   | Confidentiality (`confidentiality`)     | join of readers over everything flowing into the call (free-text bodies and URLs included) must include the destination; untrusted URLs in outgoing text checked against egress allowlist         | else BLOCK                              | A5              |
| 6   | Effect budget (`budget`)                | amount caps and send counts from the contract; repeated escalations draw down the approval budget                                                                                                 | else BLOCK                              | A11             |

Overall: any failing step -> BLOCK; else any escalating step -> ESCALATE; else ALLOW.

## Invariants

Each maps to a test; coverage table is in [threat-model.md](threat-model.md#coverage-map).

| ID  | Invariant                                                                                                       |
| --- | --------------------------------------------------------------------------------------------------------------- |
| I1  | Complete mediation: no effect outside the gateway                                                               |
| I2  | Integrity: no attacker-only value reaches a guarded parameter without ledger match or explicit user endorsement |
| I3  | Confidentiality: no labeled data reaches a principal outside its readers                                        |
| I4  | Ledger closure: ledger changes only via user-authored or user-endorsed writes                                   |
| I5  | Contract monotonicity: nothing at runtime widens the contract                                                   |
| I6  | Model independence: I1-I5 hold for ANY sequence of tool calls the LLM emits                                     |

The oracle reports I1-I6 as `InvariantResult` (`id`: `I1`..`I6`, `passed`, `detail`) in `OracleResult`.

## Event contract

Server -> client events: `run_started`, `value_labeled`, `call_proposed`, `decision_made`, `endorsement_requested`, `effect_executed`, `oracle_updated`, `run_finished`. Every event carries `run_id`, `lane` (`undefended` | `classifier` | `notary`) and `seq`. `run_started` carries the Intent Contract (and the classifier name on the classifier lane); `value_labeled` carries the label, decision unit and a text preview; `decision_made` carries the ordered reasons with codes and, for ESCALATE, the diff card; `oracle_updated` carries I1-I6 plus the attacker-goal and user-goal lights.

Client -> server commands: `endorsement_decision` (approve/reject), `hijacked_tool_call`, `poison_world`, `arena_start`.

- Defined in Pydantic: [`events.py`](../packages/core/src/notary_core/models/events.py), [`commands.py`](../packages/core/src/notary_core/models/commands.py)
- Generated JSON Schema: [`packages/schema/json/`](../packages/schema/json)
- Generated TS types and Zod: [`packages/schema/src/generated/`](../packages/schema/src/generated)
- Validated on receipt in `packages/client` (`streamRun`); invalid events throw `EventValidationError`. Commands are validated before sending (`encodeCommand`).
- Golden streams for every lane: [`packages/world/fixtures/streams/`](../packages/world/fixtures/streams); command examples: [`packages/world/fixtures/commands/`](../packages/world/fixtures/commands).

Other frozen interfaces (stubs until their phase): `decide()` in [`monitor.py`](../packages/core/src/notary_core/monitor.py), the pure Gateway and Value Store in [`gateway.py`](../packages/core/src/notary_core/gateway.py), and the `AgentRunner` hooks in [`runner.py`](../packages/core/src/notary_core/runner.py). Tagged `contracts-v1`.

Never hand-edit generated files; change the Pydantic model and run `pnpm schema:generate`.
