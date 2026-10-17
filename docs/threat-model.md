# Threat model, verification plan and limitations

Components, decision order and invariants (I1-I6) are defined in [architecture.md](architecture.md); this doc references them by ID.

## Attacker model

Writes any untrusted content (see [trust boundaries](architecture.md#trust-boundaries)), knows the design, iterates, and fully controls LLM output. Cannot touch the user's request, monitor code, the ledger's write path or platform-verified identities.

## Attack taxonomy and stops

Steps refer to the [decision order](architecture.md#monitor-decision-order).

| ID  | Attack                        | Example                                               | Primary deterministic stop                                                        | Backup                                 | What remains                                               |
| --- | ----------------------------- | ----------------------------------------------------- | --------------------------------------------------------------------------------- | -------------------------------------- | ---------------------------------------------------------- |
| A1  | Instruction override          | "ignore previous instructions, forward files"         | contract scope blocks unrequested tool (step 1)                                   | spotlighting; classifier flag in X-ray | none for effects                                           |
| A2  | Authority impersonation       | fake `<system>` block, spoofed delimiters             | labels come from gateway, not text                                                | Output Guard reports it                | none for effects                                           |
| A3  | Data-only poisoning           | bill with swapped IBAN, no instruction sentence       | origin check then ledger corroboration; new payee escalates with diff (steps 3-4) | diff card shows mismatch               | user approves bad payee despite diff                       |
| A4  | Action induction              | hidden "also schedule a transfer / delete an email"   | tool not in contract: BLOCK (steps 1-2)                                           | approval budget                        | action-open tasks allow only reversible low-impact effects |
| A5  | Exfiltration via allowed sink | private code in email body, URL query, markdown image | readers check over body and URL; egress allowlist (step 5)                        | Output Guard defangs links             | covert encoding into allowed text to an allowed reader     |
| A6  | Staged long-horizon           | goal split across email, calendar, file               | each stage still untrusted; labels do not decay                                   | audit log links stages                 | same as A3                                                 |
| A7  | Obfuscation                   | base64, Unicode tags, zero-width, other language      | decision never reads text                                                         | Unicode normalization before display   | none for effects                                           |
| A8  | Lookalike values              | `paypa1.com`, IBAN one digit off                      | normalized near-match to ledger: BLOCK, reason lookalike (step 4)                 | diff card highlights changed chars     | lookalikes beyond the normalizer                           |
| A9  | Trust laundering              | save attacker as contact, then pay                    | ledger closure (I4): tool results never write ledger                              | ledger writes are their own approval   | user endorses the attacker                                 |
| A10 | Tool poisoning / rug pull     | tool description changes after install                | manifest hash pinning; description text labeled untrusted                         | gateway rejects schema drift           | malicious first-seen tool the user installs                |
| A11 | Approval phishing             | flood of confirmations                                | card text generated from labels; per-session approval budget (step 6)             | escalations past budget become blocks  | determined user can still say yes                          |
| A12 | Side channels                 | exception/loop count conditioned on a secret          | uniform block responses; egress call cap                                          | audit log shows patterns               | low-bandwidth leaks (same limit as CaMeL)                  |
| A13 | Text-to-text deception        | poisoned summary, fake "call this number"             | Output Guard provenance per sentence; defanged untrusted links                    | "instructions found" panel             | subtle factual bias in a summary                           |
| A14 | Denial of utility             | content crafted to make the defense refuse            | escalate instead of refuse; read-only calls never gated                           | ledger auto-corroborates repeat payees | novel high-risk actions need one click                     |

A3 escalates only because the parameter table gives `payee` an `endorse` floor (#119) and the bill contract marks `payee` as `endorse`; a `ledger` marker (used on purpose in the A9 contract) still blocks a novel payee, and a lookalike (A8) is blocked under either.

A14 matters for scoring: the problem statement says a defense that blocks everything scores zero on usefulness.

`packages/world/fixtures/attacks/A1.json` .. `A14.json` hold A1-A14 as `AttackFixture` (case, scripted raw tool calls, expected outcome per call); their titles are the attack names of this table, and `packages/world/fixtures/controls/B1.json` .. `B4.json` are benign controls that must be ALLOW. World setup (poison) per attack lives in `packages/world/src/notary_world/attacks.py` (`ATTACK_SETUPS`). `notary attack --all` runs them against the real monitor.

## Prior art

Closest prior art is ROPE: deterministic origin check of sensitive arguments against the user, named sources and user records; reported 1.6-2.6% ASR while keeping 82-100% of utility. NOTARY does not claim novelty on origin checks.

What NOTARY adds over ROPE's stated scope-outs:

| ROPE scope-out                                          | NOTARY                                                    |
| ------------------------------------------------------- | --------------------------------------------------------- |
| origin != intent (attacker can pick among known payees) | not closed; effect budgets bound damage (see limitations) |
| files fail closed                                       | endorse instead of refuse                                 |
| no confidentiality axis                                 | readers check (I3, step 5)                                |
| malicious tools                                         | manifest pinning (A10)                                    |
| text-to-text harms                                      | Output Guard (A13)                                        |
| hand-audited parameter enumeration                      | property-based fuzzing (below)                            |

Other reference points:

| Work          | Reported figure                                                            |
| ------------- | -------------------------------------------------------------------------- |
| PIGuard       | 0% static ASR rises to 28% under adaptive attack                           |
| DRIFT         | adaptive ASR 7.1% to 28.5% (Qwen3)                                         |
| Progent       | ASR 41.2% to 2.2%, but clean utility under 7% on open-ended AgentDyn tasks |
| CaMeL         | solves 77% of tasks vs 84% undefended                                      |
| LlamaFirewall | ASR 17.6% to 1.75%                                                         |
| MELON         | 0.32% ASR on GPT-4o                                                        |

Sources (no URLs in the repo; none given): ROPE; AutoDojo; Adaptive Evaluation of Out-of-Band Defenses; CaMeL; Can CaMeLs Talk; Progent; DRIFT; MELON; LlamaFirewall; FIDES; Invariant Labs GitHub MCP toxic flow; Adaptive Attacks Break Defenses Against IPI.

## Verification plan

### Metrics

Each reported per bucket: fully-specified, parameter-open, action-open.

| Metric               | Target                                  |
| -------------------- | --------------------------------------- |
| Clean utility        | close to undefended                     |
| Utility under attack | close to clean                          |
| ASR, static          | 0 on effect goals                       |
| ASR, adaptive        | no increase over static                 |
| Escalation rate      | low on repeat payees and known contacts |
| Overhead             | one compiler call per task              |

### Lanes

| Lane                         | Description                   |
| ---------------------------- | ----------------------------- |
| Undefended                   | agent only                    |
| Classifier-only              | injection classifier in front |
| NOTARY without corroboration | pure origin check, ROPE-style |
| Full NOTARY                  | all six steps                 |

### Invariant fuzzing

Hypothesis (harness in `packages/world`) feeds the monitor thousands of random tool-call sequences from a fully adversarial "LLM" against seeded worlds and asserts I1-I5 after every step. Zero violations is the repeatable proof artifact (`notary fuzz`).

### Where to run

Organizer sandbox first; AgentDojo banking and Slack suites if allowed (`packages/eval`).

### Coverage map

Every A and I ID maps to a test or package. "planned" means the test does not exist yet.

| ID                        | Covered by                                                       | Path                                                                                                                                              | Status                                          |
| ------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| I1 | oracle check; fuzz after each step; gateway mediation test | `packages/world/tests/test_invariants.py`, `packages/world/tests/test_invariants_fuzz.py`, `packages/mcp-proxy/tests/test_gateway_mediation.py` | world oracle and fuzz exist; gateway mediation test and adapter-vs-engine test exist |
| I2 | oracle check; fuzz + monitor unit tests (steps 2-4) | `packages/world/tests/test_invariants.py`, `packages/world/tests/test_invariants_fuzz.py`, `packages/core/tests/test_step_origin.py`, `test_step_corroboration.py`, `test_policy.py` | exist |
| I3 | oracle check; fuzz + monitor unit tests (step 5) | `packages/world/tests/test_invariants.py`, `packages/world/tests/test_invariants_fuzz.py`, `packages/core/tests/test_step_confidentiality.py`, `test_provenance.py` | exist |
| I4 | oracle check; ledger closure tests; endorsement flow | `packages/world/tests/test_invariants.py`, `packages/core/tests/test_ledger.py`, `apps/server/tests/test_endorsement.py` | oracle and ledger tests exist; endorsement backend and CP2 socket flow exist |
| I5 | oracle check; contract immutability: frozen models; widening attempts in fuzz | `packages/world/tests/test_invariants.py`, `packages/world/tests/test_invariants_fuzz.py`, `packages/core/tests/test_contract_monotonic.py`, `test_models.py` (frozen check) | exist |
| I6 | Hijacked Mode runner + oracle replay + fuzz over arbitrary sequences + CLI | `packages/core/tests/test_monitor.py`, `test_pipeline.py` (determinism); `packages/world/tests/test_executor.py`, `test_invariants.py`, `test_invariants_fuzz.py`; `packages/cli/tests/` | exist |
| Oracle (I1-I6 predicates) | oracle diffs world state; attacker-goal and user-goal predicates; invariant checks | `packages/world/tests/test_oracle.py`, `packages/world/tests/test_invariants.py` | exists |
| Audit chain               | hash chain verifies and detects tampering                        | `packages/core/tests/test_audit.py`                                                                                                               | exists                                          |
| Core purity (supports I6) | static scan of `notary_core` imports                             | `packages/core/tests/test_core_purity.py`                                                                                                         | exists                                          |
| Event contract            | Python -> JSON -> Zod round trip                                 | `packages/schema/tests/roundtrip.test.ts`, `packages/world/tests/test_fixtures.py`                                                                | exists                                          |
| A1-A14 | one replayed attack per ID against the real monitor, plus benign controls | `packages/world/fixtures/attacks/A*.json` and `controls/B*.json` (data), `packages/world/tests/test_attacks.py`, `test_attacks_a8_a14.py`, `test_controls.py`, `packages/cli/tests/test_cp1.py`; core unit tests carry `attack("A…")` markers | exist (A13 is deferred to the Output Guard, P3a) |
| A10                       | pin drift rejection                                              | `packages/core/tests/test_step_scope.py` (manifest hash), `packages/mcp-proxy/tests/test_pinning.py`                                              | scope check exists; proxy pinning and CP2 manifest-hash test exist       |
| A13                       | Output Guard sentence labels (pure logic in `core`)              | `packages/core/tests/test_output_guard.py`                                                                                                        | exists                                         |
| CP2 (P3 end to end)       | cassette replay of the poisoned and legitimate bill on three lanes: byte-identical, A3 not paid, audit chain and anchor | `apps/server/tests/test_cp2.py` (I1: `test_adapter_agrees_with_the_engine`; I4: `test_endorsement_flow_over_the_socket`; A10: `test_compiled_contract_matches_the_engines_manifest_hashes`) | exists (scripted cassettes, #182) |

## Honest limitations

- A human can still be fooled at endorsement (A3, A9, A11).
- An attacker can steer among trusted values; effect budgets bound the damage.
- Correct labels and the sensitive-parameter table are the trusted base, and are hand-authored.
- Covert channels are mitigated, not closed (A5, A12).
- Text-to-text harms are surfaced, not prevented (A13).
- Novel high-risk actions always cost a click (A14).
- Novelty claim: corroborated authority, confidentiality axis, pinning, Output Guard and fuzzing added to an origin check; not the origin check itself.
