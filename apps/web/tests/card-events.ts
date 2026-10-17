import type { Event } from "@notary/schema";

import { load, must } from "./golden";

/**
 * Event sequences around an endorsement card, built from the golden NOTARY stream (events 0..8:
 * the run, a read, the payment proposal, its ESCALATE and `endorsement_requested e1`). What
 * follows the card is made of copies of the stream's own events in the order the real server
 * produces them (pinned by `test_what_follows_a_card` in apps/server/tests/test_cp2.py):
 *
 * - approve: `decision_made <call> ALLOW`, then the effect
 * - reject or timeout: `oracle_updated`, `run_finished`
 * - use nearest: `value_labeled`, `call_proposed <call>.nearest`, its decision
 */
const golden = load("poisoned_bill.notary");

/** The run up to and including the card: it is open. */
export const TO_REQUEST: readonly Event[] = golden.slice(0, 9);

const request = must(TO_REQUEST.at(-1), "the card");
const escalate = must(golden[7], "the ESCALATE decision");
const proposal = must(golden[6], "the payment proposal");

if (
  request.type !== "endorsement_requested" ||
  escalate.type !== "decision_made" ||
  proposal.type !== "call_proposed"
) {
  throw new Error("the golden stream changed shape");
}

export const CALL = request.endorsement.call_id;
export const CARD = request.endorsement.endorsement_id;
export const LABELED = must(golden[5], "a labeled value");
export const ORACLE = must(
  golden.find((event) => event.type === "oracle_updated"),
  "the oracle",
);
export const FINISHED = must(
  golden.find((event) => event.type === "run_finished"),
  "the end",
);

/** `events` appended to `base`, numbered after it. */
export function append(base: readonly Event[], ...events: Event[]): Event[] {
  const last = base.at(-1)?.seq ?? -1;
  return [...base, ...events.map((event, index) => ({ ...event, seq: last + 1 + index }))];
}

export function decisionFor(
  verdict: "ALLOW" | "BLOCK",
  callId: string = CALL,
  code = "STEP_PASS",
): Event {
  if (escalate.type !== "decision_made") throw new Error("unreachable");
  const reason = must(escalate.decision.reasons[0], "a reason");
  return {
    ...escalate,
    call_id: callId,
    decision: {
      ...escalate.decision,
      verdict,
      reasons: [{ ...reason, code: code as typeof reason.code }],
    },
  };
}

export function proposalFor(callId: string): Event {
  if (proposal.type !== "call_proposed") throw new Error("unreachable");
  return { ...proposal, proposal: { ...proposal.proposal, call_id: callId } };
}

/** Another card, for another call. */
export function requestFor(endorsementId: string, callId: string): Event {
  if (request.type !== "endorsement_requested") throw new Error("unreachable");
  return {
    ...request,
    endorsement: { ...request.endorsement, endorsement_id: endorsementId, call_id: callId },
  };
}

/** The run with `max_approvals` set to `value`. */
export function withBudget(events: readonly Event[], value: number): Event[] {
  return events.map((event) =>
    event.type === "run_started"
      ? {
          ...event,
          contract: {
            ...event.contract,
            budget: { ...event.contract.budget, max_approvals: value },
          },
        }
      : event,
  );
}

/** The budget of the golden run. */
export const MAX_APPROVALS = must(
  TO_REQUEST[0]?.type === "run_started" ? TO_REQUEST[0].contract.budget.max_approvals : null,
  "max_approvals",
);

/** What the server sends after each answer. */
export const APPROVED = append(TO_REQUEST, decisionFor("ALLOW"), ORACLE, FINISHED);
export const REJECTED = append(TO_REQUEST, ORACLE, FINISHED);
export const REPLACED = append(
  TO_REQUEST,
  LABELED,
  proposalFor(`${CALL}.nearest`),
  decisionFor("ALLOW", `${CALL}.nearest`),
);
export const BLOCKED = append(TO_REQUEST, decisionFor("BLOCK", CALL, "BUDGET_APPROVALS_EXHAUSTED"));
