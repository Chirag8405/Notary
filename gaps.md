# NOTARY: gaps and improvements

Written 2026-10-19 after a review of the codebase at `main` (all P6 issues closed except the epic #270). This file is for a new session: each gap says where to look, what is known, and what to do. It is not committed.

## How reliable this is

- **Read in full:** `docs/architecture.md`, `docs/threat-model.md`, the open items in `docs/phase.md`.
- **Read in part:** `packages/core/src/notary_core/monitor.py`, `steps/confidentiality.py`, `lookalike.py`, `units/host.py`, `packages/mcp-proxy/src/notary_mcp_proxy/check.py`, the proxy README config table.
- **Run:** `pnpm --filter @notary/cli cp1` (14 attacks, 4 controls, 0 mismatches; fuzz `ci` profile, 100 examples, 0 violations) and `pnpm audit --prod`. The full gate passed earlier in the session (46/46 tasks, `schema:check` clean).
- **Not done:** no line-by-line audit of the roughly 33,000 lines of source (core 4k, mcp-proxy 7.9k, world 5.9k, server 5.7k, web 3.7k, ui 3.1k, eval 1.3k). Items marked "unverified" below are suspicions to check first.

Repo rules to keep in mind (from `CLAUDE.md`): never commit to `main`; branch `p<phase>/<slug>`, one PR per issue with `Closes #n` and a ticked checkbox checklist; no agent or co-author attribution; `notary_core` stays pure; never hand-edit generated files; contract changes (new event type, model, schema) need the `contract-change` label and the P0b announcement; run `pnpm schema:generate && pnpm turbo run lint typecheck test build && pnpm schema:check` before pushing.

## Suggested order

| #   | Work                                                               | Why first                                                     |
| --- | ------------------------------------------------------------------ | ------------------------------------------------------------- |
| 1   | G1 `check` warns on `read` tools with free-text params             | Highest-value security fix; small                             |
| 2   | G16 CI workflow (plan in `next-steps.md`)                          | Replaces the manual gate; later fixes get checked             |
| 3   | G21 stale docs                                                     | Cheap; fixes how the project reads                            |
| 4   | G7 event for rejected and timed-out escalations                    | Contract change; fixes the audit gap and the stuck X-ray card |
| 5   | G12 AgentDojo harness, or another external injection set           | Independent evidence                                          |
| 6   | G17 coverage and mutation testing on `notary_core`                 | Shows whether the tests would catch a weakened check          |
| 7   | G3, G4 normalizer hardening (confusables data, Public Suffix List) | Close the documented A8 and egress approximations             |
| 8   | G19, G18 dependency advisories, root `pytest` collection           | Hygiene                                                       |
| 9   | G25, G27 real-world checks and the #270 demo check                 | Needs the user's machine and keys                             |
| 10  | G8 HTTP endpoint hardening                                         | Lower urgency; loopback is the default                        |
| 11  | G28, G29 tool annotations and a LICENSE file                       | Directory listing checks; both are small                      |

---

## A. Security design

### G1. A `read` tool skips every check (priority: high)

- **What:** `monitor.decide` allows a tool whose effective effect is `read` right after the scope check, with a single reason `READ_ONLY_UNGATED` (`packages/core/src/notary_core/monitor.py`). The reasoning is "no side effect and no outbound channel". For MCP servers the effect is declared by the user in the proxy config (`effect` in `packages/mcp-proxy/src/notary_mcp_proxy/config.py`; documented in `packages/mcp-proxy/README.md`).
- **Gap:** a tool declared `read` that takes free-text arguments (search, fetch, a URL, a query) is an ungated egress path: the agent can put secret-labeled data in an argument. `packages/mcp-proxy/src/notary_mcp_proxy/check.py` has no warning for this (verified by grep: no rule about `read` and parameters; the only `read` mention concerns resources).
- **Not verified:** a working exploit. Build a test first to confirm the behavior.
- **Do:**
  1. Add a `check` finding (start as `warning`, consider `error`) for any tool declared `read` that has a string-valued parameter not listed as a fixed enum.
  2. Add a test in `packages/mcp-proxy/tests/` and a test showing a read tool with a secret-labeled argument.
  3. Decide in the core whether a read tool that receives an argument whose readers are narrower than public should go through the confidentiality step (this would be a policy change in `notary_core`, so it needs a design note in `docs/decisions.md`).
  4. Update the README and the threat model.

### G2. The sensitive-parameter table and the labels are hand-authored (priority: medium)

- **What:** `packages/core/src/notary_core/policy/sensitive_params.py` holds the table; the threat model calls "correct labels and the sensitive-parameter table" the trusted base.
- **Gap:** for a third-party tool, a parameter nobody classified may be unguarded. `check` reports some cases (`PARAM_NOT_IN_CONFIG`, `EFFECT_STRICTER_THAN_CONFIG`); the default for a new, unclassified `write` or `irreversible` parameter should be confirmed to fail closed.
- **Do:** write tests that propose calls with an unclassified parameter on a write tool and assert the verdict is BLOCK or ESCALATE, not ALLOW. If it is ALLOW, change the default.

### G3. Lookalike normalizer is a small hand-written table (priority: medium)

- **What:** `packages/core/src/notary_core/lookalike.py` has about 25 confusable characters (Cyrillic, Greek, digits) plus `rn`/`vv`/`cl` pairs. The file says so ("Known gap").
- **Do:** vendor the Unicode confusables data as a static table (no network, no I/O at runtime, so `notary_core` stays pure), regenerate it with a script, and add property tests. Keep the exact-match rule for IBAN and amount units.

### G4. `registrable_domain` is an approximation (priority: medium)

- **What:** `packages/core/src/notary_core/units/host.py::registrable_domain` takes the last two labels, or three for a small hand-written `MULTIPART_SUFFIXES` list. No Public Suffix List.
- **Gap:** shared-hosting suffixes (`github.io`, `vercel.app`, `s3.amazonaws.com`) are not treated as suffixes, so an allowlist entry for one could admit every tenant. Used by `steps/confidentiality.py` for egress.
- **Do:** vendor a Public Suffix List snapshot as data and use it, with tests for private-suffix cases; keep `notary_core` pure (data file read at import must not count as I/O in the purity test, so embed it as Python data).

### G5. Same-user processes can approve and forge trusted input (priority: medium, documented)

- **What:** `docs/threat-model.md`, "Approvals through the MCP proxy" and "The user's prompt as a trusted value". An agent with a shell can use the control socket (`notary-mcp-proxy approve e1`, or `{"op": "user_prompt"}`).
- **Do:** options named in the doc: a one-time code shown only to the user's channel, and making the guard hook the default in the README quick start. Check whether the guard hook can be bypassed through any other tool that runs code.

### G6. Accepted limits (no action unless the scope changes)

- A human can be fooled at the card (A3, A9, A11); covert channels (A5, A12) and subtle text bias (A13) are mitigated, not closed; novel high-risk actions cost a click (A14). Listed in `docs/threat-model.md`, "Honest limitations".

### G7. Rejected and timed-out escalations have no audit event (priority: high, contract change)

- **What:** the chain shows `endorsement_requested` and nothing after it. The outcome is only in the free-text `run_finished` summary (lost if the run is killed) and on stderr. The X-ray card stays on "Sending..." after a Reject (#262).
- **Do:** file an issue with the `contract-change` label; add an event type or a field in the Pydantic model in `packages/core/src/notary_core/models/events.py`; run `pnpm schema:generate`; regenerate fixtures; update `docs/architecture.md` (event contract) and the threat model; post the P0b announcement. Keep the golden streams stable or regenerate them deliberately.

### G8. HTTP endpoint hardening (priority: low)

- **What:** `serve --http` uses one static bearer token, no TLS, no rate limit on failed tokens (`docs/threat-model.md`, "The MCP proxy as a network service"). OAuth 2.1 is not supported.
- **Do:** add failed-token throttling, or state loopback-only in the README quick start; document a TLS reverse-proxy recipe.

### G9. A poisoned first `tools/list` is pinned as is (priority: low, documented)

- Pinning stops rug pulls, not a server that is malicious from the start (A10, "malicious first-seen tool"). Possible improvement: a first-seen review step in `check` that shows descriptions for approval.

### G10. Resource URIs and prompt arguments bypass the monitor (priority: medium, contract change)

- **What:** chosen by the agent, they reach the allow-listed server without a decision (a read is not a tool call). Documented in `docs/threat-model.md`, "Honest limitations".
- **Do:** route them through the monitor or a restricted check; fixing it is a contract change.

---

## B. Evidence

### G11. The attack library is self-authored (priority: medium)

- A1–A14 and B1–B4 (`packages/world/fixtures/attacks/`, `controls/`) passed `pnpm --filter @notary/cli cp1`. They show the design handles the attacks its authors wrote down. The attacker arena (`notary_server.arena`) is the only adaptive attacker and is optional and short.
- **Do:** get attacks from outside the project (published injection sets, a second author), add them as fixtures, and run an adaptive attacker with more rounds.

### G12. No standard benchmark (priority: high)

- `packages/eval/src/notary_eval/results.py` line 31 raises `NotImplementedError` (the AgentDojo harness stub; `docs/phase.md` lines 181 and 183). Without it, results cannot be compared to the papers in the threat model.
- **Do:** implement the harness for the banking and Slack suites (if the licence allows), or another published benchmark; export JSON; then the charts and the deck numbers (`phase.md` lines 183 and 185).

### G13. Committed cassettes are scripted (priority: medium)

- `docs/phase.md` line 109: the cassettes are `scripted-v1`; real-model recordings exist but are not committed because 17 CP2 tests assume the scripted agent is hijacked.
- **Do:** make those tests not depend on a hijacked agent, or keep both a scripted and a real set of cassettes, so end-to-end replay covers real model output.

### G14. The live MCP run showed no hijack to block (priority: low)

- 2026-10-19, `claude-sonnet-5-5`: 0/20 attack success on both lanes (recorded in `docs/demo.md`). It shows utility, not blocking. Consider a run with a smaller model (the live script has no `--model` option; adding one is a small change in `packages/eval/scripts/run_mcp_live.py` and `claude_argv` in `packages/eval/src/notary_eval/mcp_eval.py`).

### G15. Fuzz depth (priority: low)

- CP1 uses the `ci` profile, 100 examples. A deeper nightly profile is not scheduled (no CI).

---

## C. Process and operations

### G16. No CI (priority: high)

- `.github/` does not exist; the gate is run by hand. The full plan (tiers, decision-diff against `main`, contract-change detector, PR-body lint, nightly fuzz, manual live-eval workflow) is in `next-steps.md`, section "CI workflow plan". Open questions there: runners, decision-diff strictness, scheduled live evals, public or private repo.
- **Do first:** `static`, `unit`, `build`, `schema-drift`, `core-purity`, `ci-ok`, then branch protection on `main` (a repo setting the owner changes).

### G17. No coverage or mutation testing (priority: medium)

- `coverage` is not installed (`import coverage` fails), so there is no coverage number for about 1,700 tests.
- **Do:** add `pytest-cov` as a dev dependency and report coverage for `notary_core` and `notary_mcp_proxy`; run a mutation tool (for example `mutmut` or `cosmic-ray`) on `packages/core/src/notary_core/steps/` and `monitor.py` to check that the tests notice a weakened check.

### G18. Root `pytest` does not collect (priority: low)

- `uv run --no-sync pytest --collect-only -q` at the root reports 22 collection errors ("import file mismatch") from test files with the same name in different packages. Per-package runs work, which is how the scripts run them.
- **Do:** add `__init__.py`/unique names, or `--import-mode=importlib` in the pytest config, and check the gate still passes.

### G19. Dependency advisories (priority: medium)

- `pnpm audit --prod`: 4 findings (2 critical, 1 high, 1 moderate). `handlebars` via `packages/config-eslint > eslint-plugin-boundaries > @boundaries/elements`; `braces` via `apps/web > shadcn > fast-glob > micromatch`. All sit in dev tooling, not runtime code.
- **Do:** upgrade or override the packages, or document a waiver in `docs/decisions.md`. Add `pnpm audit` and a Python audit to the weekly job when CI exists.

### G20. Open decisions (priority: low)

- PyPI package name and ownership (`docs/decisions.md`); the ownership map in `docs/phase.md` line 73 ("decided to leave it").

---

## D. Documentation and code hygiene

### G21. Stale status text (priority: medium, cheap)

- `docs/architecture.md`, Components table: "Reference Monitor ... stub (`NotImplementedError`)", "Trusted Ledger ... model only", and "planned" in the repo-path column for the Value Store, Intent Compiler, Quarantined Extractor and Output Guard, although the code exists (`monitor.py` implements `decide`; `output_guard.py`, `ledger.py`, `store.py` are present). `monitor.py` module docstring still says "Reference monitor (stub)". The "Other frozen interfaces (stubs until their phase)" paragraph near the end of `architecture.md` has the same problem.
- `CLAUDE.md` does not list `docs/PROJECT_GUIDE.md` (601 lines) in its docs section.
- **Do:** update the status column and the docstring in one PR; per the repo rule, doc changes go in the same commit as the behavior they describe.

### G22. Very dense docs (priority: low)

- Single paragraphs in `docs/architecture.md` run to several hundred words (the Endorsement Service and the Wiring paragraphs). Split into subsections or move the detail to `decisions.md`, so changes are reviewable.

### G23. Suppressions and broad excepts (priority: low, unverified)

- 17 `type: ignore` / `noqa` / `eslint-disable` comments and 19 `except Exception` / bare `except` clauses outside tests (counted by grep). Probably justified in fail-closed code, but not reviewed individually. Review each and add a one-line reason where missing.

### G24. Stray marker (priority: low)

- A `TODO`/`FIXME`/`XXX`/`HACK` match in `packages/eval/src/notary_eval/mcp_eval.py`. Check whether it is real.

---

## E. Product and real-world fit

### G25. Toy world and two tried servers (priority: medium)

- Everything runs on the seeded bank world; the MCP proxy has been tried on that and a GitHub-style server. The filesystem tasks (`NOTARY_EVAL_NPX=1`, tool names in `packages/eval/fixtures/mcp/filesystem.json` unverified against the real server) and a real GitHub server run are not done.

### G26. Deck and charts (priority: low)

- Slide deck numbers and charts from the export do not exist (`docs/phase.md` lines 183 and 185); depends on G12.

### G27. Epic #270 is not closed (priority: medium, needs the user)

- Open: the demo check in a normal Claude Code session with the guard hook and `/x-ray` (ALLOW, then BLOCK `LEDGER_NOT_FOUND`, then ALLOW; approve an escalation from the card with `NOTARY_MCP_APPROVALS=1`, X-ray opened as `localhost:3000`), then tick the P6 line in `docs/phase.md` (line 182). Then the user decides whether to close #270.
- Other live checks only the user can run: #258, #259 (including `claude -p` behavior), #261, #262, #264, #265, #266, #267, #269. Listed in `next-steps.md`.

---

## F. Directory quality checks

### G28. MCP tools declare no annotations (priority: medium, directory quality check)

- A directory quality check reports "No tools have read-only/destructive annotations": 14/14 tools are missing one or more hints (`add_contact`, `create_event`, `delete_email`, and 11 more). All four hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) must be explicit booleans on every tool. OpenAI's directory rejects a tool where any hint is missing or non-boolean.
- **Where to look:** the 14 tools are the seeded world's registry in `packages/world/src/notary_world/tools.py`, and the `annotations` field the proxy passes through in `packages/mcp-proxy/src/notary_mcp_proxy/mcp_backend.py` (lines 330-386). Check which server surface the checker scans (the `notary-bank` MCP server exposes only `add_contact`, `pay_bill`, `read_inbox`).
- **Do:** set all four hints per tool to match the handler's real behavior (for example `delete_email`: destructive, not read-only; `read_inbox`: read-only). Decide whether they derive from the existing effect and irreversibility metadata in the tool registry so they cannot drift. If the annotations ride in tool definitions, check whether this changes the pinned `tools/list` hash (G9) or a contract. Add a test that every registered tool has four boolean hints.

### G29. No LICENSE file (priority: medium, cheap)

- The repo has no `LICENSE` and no `license` field in `pyproject.toml` or `package.json`. The same quality check flags it, and without one nobody may legally reuse the code.
- **Do:** the user picks the license (MIT or Apache-2.0 are the usual choices; Apache-2.0 adds a patent grant). Add `LICENSE`, set the `license` field in the root and package manifests, and mention it in the README.

---

## Still pending from earlier sessions

- Post the #284 and #265 (`POST /mcp/compile`) contract-change announcements (`next-steps.md`, Decisions 3).
- Follow-up issues the advisor suggested: `serve` prints a traceback on an invalid config while `check` reports it cleanly; `check` could warn about per-field settings that match no declared output field.
- #240 finished with a partial run (two models, 10 rounds); a larger run with `qwen/qwen3.8-27b` can follow.
- Clean up old worktrees in `.claude/worktrees/` (`git worktree remove <path>`, delete the `worktree-agent-*` branches).
