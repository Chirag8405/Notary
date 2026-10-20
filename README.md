# NOTARY

[![M8ven Score](https://m8ven.ai/badge/mcp/chirag8405-notary-1vupkx?v=a4ad71377c8a7e0474fa924f951668ee)](https://m8ven.ai/mcp/chirag8405-notary-1vupkx?s=readme)

A deterministic security layer that stops indirect prompt injection in AI agents.

NOTARY assumes the agent's LLM is fully hijacked, then makes sure nothing the attacker wants can still happen. The guarantee comes from a small reference monitor that checks every proposed tool call against what the user actually asked for. It does not depend on prompts or classifiers.

> **Status:** under active development. The monitor, gateway, agent runner, server event stream, Trust X-ray UI, judge playground and MCP proxy are implemented. The AgentDojo benchmark harness is still a stub (`NotImplementedError`). [`docs/phase.md`](docs/phase.md) tracks each item.

## How it works

1. **Freeze the intent.** The user's request is compiled into an `IntentContract`: the allowed tools, a marker for each sensitive parameter, and an effect budget. The compiler never sees fetched content.
2. **Label every value.** Each value gets a provenance `Label` (origin, integrity, readers). Labels come from the gateway, never from text, so spoofed delimiters and obfuscated payloads have no effect. The monitor never reads raw content.
3. **Decide each call.** A pure function, `monitor.decide(contract, proposal, values, ledger)`, returns `ALLOW`, `ESCALATE` or `BLOCK` with ordered reasons.
4. **Log it.** Every decision goes into a tamper-evident audit hash chain and appears live in the Trust X-ray UI.

Untrusted content can still supply values, such as a payee on a bill. A value only gains authority over a consequential action when the user's own trusted state corroborates it, so "pay this bill" keeps working.

### Monitor checks

The checks run in this order. Any failure is a `BLOCK`. Otherwise any escalation is an `ESCALATE`. Otherwise the call is allowed.

| #   | Check             | Question                                                 |
| --- | ----------------- | -------------------------------------------------------- |
| 1   | `scope`           | Is the tool, and every parameter, within the contract?   |
| 2   | `irreversibility` | Does an irreversible effect have explicit authorization? |
| 3   | `origin`          | Do argument labels satisfy the per-parameter markers?    |
| 4   | `corroboration`   | Does the ledger corroborate untrusted-origin values?     |
| 5   | `confidentiality` | Would data flow to a principal outside its readers?      |
| 6   | `budget`          | Does the call fit the remaining effect budget?           |

### Invariants

| ID  | Invariant                                                                                                         |
| --- | ----------------------------------------------------------------------------------------------------------------- |
| I1  | Complete mediation: no effect occurs outside the gateway                                                          |
| I2  | Integrity: no attacker-only value reaches a guarded parameter without a ledger match or explicit user endorsement |
| I3  | Confidentiality: no labeled data reaches a principal outside its readers                                          |
| I4  | Ledger closure: the ledger changes only through user-authored or user-endorsed writes                             |
| I5  | Contract monotonicity: nothing at runtime widens the contract                                                     |
| I6  | Model independence: I1 to I5 hold for any sequence of tool calls the LLM emits                                    |

The attack taxonomy (A1 to A14), prior art and known limitations are in [`docs/threat-model.md`](docs/threat-model.md).

## Repository layout

| Path                            | Purpose                                                                                                                                      |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/core`                 | Pure, deterministic monitor, ledger, audit chain and the Pydantic models every type originates from. No I/O, randomness, clock or LLM calls. |
| `packages/world`                | Seeded sandbox world, attack fixtures and golden event streams                                                                               |
| `packages/mcp-proxy`            | Tool-calling I/O adapter for the gateway                                                                                                     |
| `packages/cli`, `packages/eval` | Command line, oracle and evaluation harness                                                                                                  |
| `packages/schema`               | Generated JSON Schema, TypeScript types and Zod validators                                                                                   |
| `packages/client`               | Generated API client and validated event stream                                                                                              |
| `packages/ui`                   | Trust X-ray components                                                                                                                       |
| `apps/server`                   | HTTP and event-stream server                                                                                                                 |
| `apps/web`                      | Next.js app hosting the Trust X-ray at `/x-ray`                                                                                              |

Dependency directions are enforced by import-linter (Python) and `eslint-plugin-boundaries` (TypeScript); a violation fails `lint`. See [`CLAUDE.md`](CLAUDE.md) for the full map.

## Getting started

Requirements: Node >= 24, pnpm >= 12, [uv](https://docs.astral.sh/uv/) and Python 3.12.

```sh
pnpm install && uv sync
pnpm dev
```

This starts the server on <http://localhost:8000> and the web app on <http://localhost:3000>. Open <http://localhost:3000/x-ray> for the Trust X-ray.

To run the same demo in containers:

```sh
docker compose up
```

## Development

Types originate in Pydantic models in `packages/core`. Generated files are never edited by hand: change the model, then regenerate.

```sh
pnpm schema:generate     # core -> JSON Schema -> TS types and Zod; OpenAPI -> client; event fixtures
pnpm schema:check        # regenerate and fail on drift
```

Before pushing, run the full gate:

```sh
pnpm schema:generate && pnpm turbo run lint typecheck test build && pnpm schema:check
```

Work happens on a branch (`p<phase>/<slug>`), one pull request per issue, never directly on `main`. Use `uv run --no-sync` inside package scripts and run `uv sync` yourself, since parallel `uv run` calls can corrupt the environment.

## Documentation

| Doc                                            | Contents                                                                 |
| ---------------------------------------------- | ------------------------------------------------------------------------ |
| [`docs/architecture.md`](docs/architecture.md) | Trust boundaries, components, decision order, invariants, event contract |
| [`docs/threat-model.md`](docs/threat-model.md) | Attacks A1 to A14, prior art, verification plan, limitations             |
| [`docs/demo.md`](docs/demo.md)                 | Determinism, Trust X-ray, judge playground, stage script                 |
| [`docs/phase.md`](docs/phase.md)               | Build phases, checkpoints, risks                                         |
| [`docs/decisions.md`](docs/decisions.md)       | Tool and design choices                                                  |
| [`CLAUDE.md`](CLAUDE.md)                       | Repo rules and conventions                                               |

## Prior art

The closest prior work is ROPE, which checks the origin of sensitive arguments against the user, named sources and user records. NOTARY does not claim novelty on origin checks. It adds corroboration against a user-controlled ledger, confidentiality tracking, and a model-independent test mode ("Hijacked Mode") in which a person submits raw tool calls and the monitor still holds. Details are in the threat model.

## License

NOTARY is released under the [MIT License](LICENSE). See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to contribute.
