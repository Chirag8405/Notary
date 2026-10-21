import type { AttackCase, AttackRunResponse, CheckSummary } from "@notary/client";
import { reasonTextFor, verdictText } from "@/lib/plain-language";

/**
 * Pure helpers of the "Attack library" panel: the card hints and how the server's check results
 * become table rows. No React, no I/O, no clock or randomness.
 */

export const CONTROL_IDS = ["B1", "B2", "B3", "B4"] as const;

/** The "Primary stop" column of docs/threat-model.md, shown as the card's hint. */
export const PRIMARY_STOPS: Readonly<Record<AttackCase["id"], string>> = {
  A1: "contract scope blocks unrequested tool (step 1)",
  A2: "labels come from gateway, not text",
  A3: "origin check then ledger corroboration; new payee escalates with diff (steps 3-4)",
  A4: "tool not in contract: BLOCK (steps 1-2)",
  A5: "readers check over body and URL; egress allowlist (step 5)",
  A6: "each stage still untrusted; labels do not decay",
  A7: "decision never reads text",
  A8: "normalized near-match to ledger: BLOCK, reason lookalike (step 4)",
  A9: "ledger closure (I4): tool results never write ledger",
  A10: "manifest hash pinning; description text labeled untrusted",
  A11: "card text generated from labels; per-session approval budget (step 6)",
  A12: "uniform block responses; egress call cap",
  A13: "Output Guard provenance per sentence; defanged untrusted links",
  A14: "escalate instead of refuse; read-only calls never gated",
};

/** "ALLOW READ_ONLY_UNGATED", "ESCALATE corroboration LEDGER_NOVEL_ESCALATE", "none" for null. */
export function describeOutcome(outcome: CheckSummary["expected"] | null): string {
  if (outcome === null) return "none";
  return [outcome.verdict, outcome.deciding_check, outcome.code]
    .filter((part) => part !== null)
    .join(" ");
}

/** The expected outcome as a sentence: what NOTARY does, and why. */
export function plainOutcome(outcome: CheckSummary["expected"] | null): string {
  if (outcome === null) return "Nothing is expected.";
  const verdict = verdictText(outcome.verdict).label;
  const why = outcome.code === null ? null : reasonTextFor(outcome.code);
  return why === null ? verdict : `${verdict}: ${why}`;
}

export interface CheckRow {
  callId: string;
  tool: string;
  expected: string;
  actual: string;
  matches: boolean;
}

/** One row per check, in response order. */
export function checkRows(checks: readonly CheckSummary[]): readonly CheckRow[] {
  return checks.map((check) => ({
    callId: check.call_id,
    tool: check.tool,
    expected: describeOutcome(check.expected),
    actual: describeOutcome(check.actual),
    matches: check.matches,
  }));
}

export type RunBadge = "matches" | "mismatch" | "deferred";

/** `deferred` wins: a deferred class is not judged by the monitor's verdicts. */
export function runBadge(run: Pick<AttackRunResponse, "ok" | "deferred">): RunBadge {
  if (run.deferred) return "deferred";
  return run.ok ? "matches" : "mismatch";
}

export const BADGE_TEXT: Readonly<Record<RunBadge, string>> = {
  matches: "Monitor matches the taxonomy",
  mismatch: "MISMATCH: the monitor decided differently",
  deferred: "Deferred to the Output Guard",
};

export const DEFERRED_TEXT =
  "This class is output behavior: the monitor only has to allow the benign read. The Output Guard (P3a) handles the text.";

/** The cards' order: by the number after "A" (A2 before A10), not by string. */
export function compareAttacks(a: Pick<AttackCase, "id">, b: Pick<AttackCase, "id">): number {
  return Number(a.id.slice(1)) - Number(b.id.slice(1));
}
