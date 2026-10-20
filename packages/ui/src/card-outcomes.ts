import type { Event } from "@notary/schema";

/**
 * What the run's own stream says happened to an endorsement card.
 *
 * The agent runner is sequential and blocks on a card: the broker registers the card before
 * `endorsement_requested` leaves the runner, and no later event is produced until the card is
 * answered, timed out or cancelled. So the first event after the request (skipping the
 * `value_labeled` events that precede a proposal) is the outcome. Since #302 that event is
 * `endorsement_resolved`, which names the outcome; a stream recorded before it fell back to the
 * rules below:
 *
 * - `endorsement_resolved` for the card: `approved` (then the call's own decision says whether
 *   the monitor allowed it: `approved` or `blocked`), `replaced`, `rejected`, `timed_out` or
 *   `cancelled`.
 * - `decision_made` for the card's call, ALLOW: the user approved (`approved`).
 * - `decision_made` for the card's call, BLOCK: approved, then refused (`blocked`).
 * - `call_proposed` for `<call_id>.nearest`: the user asked for the nearest known value
 *   (`replaced`); that new call is judged like any other.
 * - anything else (the oracle, the end of the run, another call): the card was not approved
 *   (`closed`). An old stream cannot tell a rejection from a timeout or a cancel; the user's own
 *   click can.
 * - no event yet: `open`.
 */
export type CardOutcome =
  | { kind: "open" }
  | { kind: "approved"; decisionSeq: number }
  | { kind: "replaced"; proposalSeq: number }
  | { kind: "blocked"; decisionSeq: number; code: string }
  | { kind: "rejected"; resolvedSeq: number }
  | { kind: "timed_out"; resolvedSeq: number }
  | { kind: "cancelled"; resolvedSeq: number }
  | { kind: "closed"; nextSeq: number };

export interface CardOutcomes {
  /** One outcome per `endorsement_requested` of the stream, by endorsement id. */
  byEndorsementId: ReadonlyMap<string, CardOutcome>;
  /**
   * The approvals left when the card was raised: `max_approvals` of the run's contract minus the
   * cards approved before it; null before `run_started`. Replacing a value uses no approval.
   */
  remainingBefore: ReadonlyMap<string, number | null>;
}

/** The suffix of the call the server proposes for "use the nearest known value". */
const NEAREST_SUFFIX = ".nearest";

/** What `endorsement_resolved` says, with what the stream shows of the work that followed. */
function resolvedOutcome(
  events: readonly Event[],
  resolvedIndex: number,
  outcome: "approved" | "rejected" | "replaced" | "timed_out" | "cancelled",
  resolvedSeq: number,
  callId: string,
): CardOutcome {
  if (outcome === "rejected" || outcome === "timed_out" || outcome === "cancelled") {
    return { kind: outcome, resolvedSeq };
  }
  for (let index = resolvedIndex + 1; index < events.length; index += 1) {
    const next = events[index];
    if (next === undefined || next.type === "value_labeled") continue;
    if (outcome === "replaced") {
      if (next.type === "call_proposed" && next.proposal.call_id === `${callId}${NEAREST_SUFFIX}`) {
        return { kind: "replaced", proposalSeq: next.seq };
      }
      break;
    }
    if (next.type === "decision_made" && next.call_id === callId) {
      if (next.decision.verdict === "BLOCK") {
        return {
          kind: "blocked",
          decisionSeq: next.seq,
          code: next.decision.reasons.at(-1)?.code ?? "",
        };
      }
      return { kind: "approved", decisionSeq: next.seq };
    }
    break;
  }
  // The answer is logged; the work it causes has not arrived yet.
  return outcome === "replaced"
    ? { kind: "replaced", proposalSeq: resolvedSeq }
    : { kind: "approved", decisionSeq: resolvedSeq };
}

function outcomeAfter(
  events: readonly Event[],
  requestIndex: number,
  endorsementId: string,
  callId: string,
): CardOutcome {
  for (let index = requestIndex + 1; index < events.length; index += 1) {
    const next = events[index];
    if (next === undefined || next.type === "value_labeled") continue;
    if (next.type === "endorsement_resolved" && next.endorsement_id === endorsementId) {
      return resolvedOutcome(events, index, next.outcome, next.seq, callId);
    }
    if (next.type === "decision_made" && next.call_id === callId) {
      if (next.decision.verdict === "ALLOW") return { kind: "approved", decisionSeq: next.seq };
      if (next.decision.verdict === "BLOCK") {
        const last = next.decision.reasons.at(-1);
        return { kind: "blocked", decisionSeq: next.seq, code: last?.code ?? "" };
      }
    }
    if (next.type === "call_proposed" && next.proposal.call_id === `${callId}${NEAREST_SUFFIX}`) {
      return { kind: "replaced", proposalSeq: next.seq };
    }
    return { kind: "closed", nextSeq: next.seq };
  }
  return { kind: "open" };
}

/** Pure and order-only: the same events in the same order give the same outcomes. */
export function cardOutcomes(events: readonly Event[]): CardOutcomes {
  const byEndorsementId = new Map<string, CardOutcome>();
  const remainingBefore = new Map<string, number | null>();
  let maxApprovals: number | null = null;
  let approved = 0;
  events.forEach((event, index) => {
    if (event.type === "run_started") {
      maxApprovals = event.contract.budget.max_approvals;
      return;
    }
    if (event.type !== "endorsement_requested") return;
    const id = event.endorsement.endorsement_id;
    const outcome = outcomeAfter(events, index, id, event.endorsement.call_id);
    remainingBefore.set(id, maxApprovals === null ? null : Math.max(maxApprovals - approved, 0));
    byEndorsementId.set(id, outcome);
    if (outcome.kind === "approved") approved += 1;
  });
  return { byEndorsementId, remainingBefore };
}
