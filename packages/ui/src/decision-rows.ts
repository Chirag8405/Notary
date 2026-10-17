import type { Decision, Origin, Reason, ValueRef } from "@notary/schema";

import type { CallView, RunView } from "./run-view";

/**
 * One row of the decision stream per proposed call, folded from a RunView. Pure and
 * deterministic: no React, clock or randomness, and the view is never mutated.
 */

export interface ArgChip {
  param: string;
  originKind: Origin["kind"];
  /** The tool's name for a tool origin, else null. */
  originName: string | null;
  integrity: ValueRef["label"]["integrity"];
  /** The first 8 characters of the value's content hash. */
  hashShort: string;
  valueId: string;
  /** The redacted preview from the view; empty while the value has not been labeled yet. */
  preview: string;
}

export interface EarlierDecision {
  verdict: Decision["verdict"];
  headlineReason: Reason | null;
  seq: number;
}

export interface DecisionRow {
  callId: string;
  seq: number;
  tool: string;
  manifestShort: string;
  args: readonly ArgChip[];
  /** Null when the call has no decision (a lane without the monitor, or one still pending). */
  verdict: Decision["verdict"] | null;
  /** As received, never re-sorted. */
  reasons: readonly Reason[];
  headlineReason: Reason | null;
  /** The effect summary. */
  executed: string | null;
  endorsementId: string | null;
  /** Decisions before the latest one, oldest first (an approved escalation is decided twice). */
  earlierDecisions: readonly EarlierDecision[];
}

const SHORT = 8;

/** The first 8 characters of a hash, without a leading "<algorithm>:" prefix if there is one. */
export function shortHash(hash: string): string {
  return hash.slice(hash.lastIndexOf(":") + 1, hash.lastIndexOf(":") + 1 + SHORT);
}

/** The first reason that is not a pass; else the last reason; null when there are none. */
export function headlineReason(reasons: readonly Reason[]): Reason | null {
  return reasons.find((reason) => reason.outcome !== "pass") ?? reasons[reasons.length - 1] ?? null;
}

/** The legacy one-line summary of a decision; the same text `describeEvent` gives its event. */
export function decisionSummary(callId: string, verdict: Decision["verdict"]): string {
  return `${verdict} for ${callId}`;
}

function byText(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

function chipsOf(call: CallView, previews: ReadonlyMap<string, string>): ArgChip[] {
  return Object.keys(call.args)
    .sort(byText)
    .flatMap((param) => {
      const ref = call.args[param];
      if (ref === undefined) return [];
      const origin = ref.label.origin;
      return [
        {
          param,
          originKind: origin.kind,
          originName: origin.kind === "tool" ? origin.name : null,
          integrity: ref.label.integrity,
          hashShort: shortHash(ref.content_hash),
          valueId: ref.id,
          preview: previews.get(ref.id) ?? "",
        },
      ];
    });
}

function rowOf(call: CallView, previews: ReadonlyMap<string, string>): DecisionRow {
  const reasons = call.decision === null ? [] : [...call.decision.reasons];
  return {
    callId: call.callId,
    seq: call.proposedSeq,
    tool: call.tool,
    manifestShort: shortHash(call.manifestHash),
    args: chipsOf(call, previews),
    verdict: call.decision === null ? null : call.decision.verdict,
    reasons,
    headlineReason: headlineReason(reasons),
    executed: call.executed === null ? null : call.executed.summary,
    endorsementId: call.endorsementId,
    earlierDecisions: call.decisionHistory.map((record) => ({
      verdict: record.decision.verdict,
      headlineReason: headlineReason(record.decision.reasons),
      seq: record.seq,
    })),
  };
}

/** One row per call, ordered by proposed seq then call id. */
export function toDecisionRows(view: RunView): readonly DecisionRow[] {
  const previews = new Map(view.values.map((value) => [value.ref.id, value.preview]));
  return [...view.calls]
    .sort((a, b) => a.proposedSeq - b.proposedSeq || byText(a.callId, b.callId))
    .map((call) => rowOf(call, previews));
}
