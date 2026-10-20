import type { Event } from "@notary/schema";
import { describe, expect, it } from "vitest";

import { cardOutcomes } from "../src/card-outcomes";
import { load, must } from "./golden";

/**
 * The golden NOTARY stream up to and including its card (events 0..8: c1 read, c2 pay, ESCALATE,
 * `endorsement_requested e1`). What follows the card is built from copies of its own events, in
 * the order the real server produces them (checked in apps/server/tests/test_cp2.py).
 */
const golden = load("poisoned_bill.notary");
const toRequest = golden.slice(0, 9);
const REQUEST = must(toRequest.at(-1), "the card");
const ESCALATE = must(golden[7], "the ESCALATE decision");
const PROPOSAL = must(golden[6], "the payment proposal");
const LABELED = must(golden[5], "a labeled value");
const ORACLE = must(
  golden.find((event) => event.type === "oracle_updated"),
  "the oracle",
);
const FINISHED = must(
  golden.find((event) => event.type === "run_finished"),
  "the end",
);

if (
  REQUEST.type !== "endorsement_requested" ||
  ESCALATE.type !== "decision_made" ||
  PROPOSAL.type !== "call_proposed"
) {
  throw new Error("the golden stream changed shape");
}
const CALL = REQUEST.endorsement.call_id;
const CARD = REQUEST.endorsement.endorsement_id;

/** `events` renumbered from the end of `toRequest`. */
function after(...events: Event[]): Event[] {
  return [...toRequest, ...events.map((event, index) => ({ ...event, seq: 9 + index }))];
}

function decision(verdict: "ALLOW" | "BLOCK", callId = CALL, code = "STEP_PASS"): Event {
  if (ESCALATE.type !== "decision_made") throw new Error("unreachable");
  const reason = must(ESCALATE.decision.reasons[0], "a reason");
  return {
    ...ESCALATE,
    call_id: callId,
    decision: {
      ...ESCALATE.decision,
      verdict,
      reasons: [{ ...reason, code: code as typeof reason.code }],
    },
  };
}

function proposal(callId: string): Event {
  if (PROPOSAL.type !== "call_proposed") throw new Error("unreachable");
  return { ...PROPOSAL, proposal: { ...PROPOSAL.proposal, call_id: callId } };
}

function outcomeOf(events: readonly Event[], id = CARD) {
  return must(cardOutcomes(events).byEndorsementId.get(id), `an outcome for ${id}`);
}

describe("cardOutcomes", () => {
  it("is open while the card is the last event, with every approval left", () => {
    const result = cardOutcomes(toRequest);
    expect(outcomeOf(toRequest)).toEqual({ kind: "open" });
    const budget = must(
      toRequest[0]?.type === "run_started" ? toRequest[0].contract.budget.max_approvals : null,
      "max_approvals",
    );
    expect(result.remainingBefore.get(CARD)).toBe(budget);
  });

  it("an ALLOW for the card's call is an approval [I4]", () => {
    const events = after(decision("ALLOW"));
    expect(outcomeOf(events)).toEqual({ kind: "approved", decisionSeq: 9 });
  });

  it("an approval is followed by its effect and still reads as approved", () => {
    const events = after(decision("ALLOW"), ORACLE, FINISHED);
    expect(outcomeOf(events).kind).toBe("approved");
  });

  it("a BLOCK for the card's call carries the last reason code", () => {
    const events = after(decision("BLOCK", CALL, "BUDGET_APPROVALS_EXHAUSTED"));
    expect(outcomeOf(events)).toEqual({
      kind: "blocked",
      decisionSeq: 9,
      code: "BUDGET_APPROVALS_EXHAUSTED",
    });
  });

  it("the oracle and the end of the run mean the card was not approved (reject or timeout)", () => {
    const events = after(ORACLE, FINISHED);
    expect(outcomeOf(events)).toEqual({ kind: "closed", nextSeq: 9 });
  });

  it("the nearest known value is its own outcome, past the value that was labeled [I2]", () => {
    const events = after(
      LABELED,
      proposal(`${CALL}.nearest`),
      decision("ALLOW", `${CALL}.nearest`),
    );
    expect(outcomeOf(events)).toEqual({ kind: "replaced", proposalSeq: 10 });
  });

  it("a decision for another call right after the card is not an approval", () => {
    const events = after(decision("ALLOW", "c9"));
    expect(outcomeOf(events)).toEqual({ kind: "closed", nextSeq: 9 });
  });

  it("another proposal after the card means the run moved on", () => {
    const events = after(LABELED, proposal("c9"));
    expect(outcomeOf(events)).toEqual({ kind: "closed", nextSeq: 10 });
  });

  it("only value_labeled events after the card still leave it open", () => {
    const events = after(LABELED, LABELED);
    expect(outcomeOf(events)).toEqual({ kind: "open" });
  });

  it("two cards: approvals left count only the approved ones, not rejected or replaced", () => {
    const second = (id: string, call: string): Event => ({
      ...REQUEST,
      endorsement: { ...REQUEST.endorsement, endorsement_id: id, call_id: call },
    });
    const events = after(
      decision("ALLOW"), // e1 approved
      second("e2", "c3"),
      ORACLE, // e2 closed
      second("e3", "c4"),
      LABELED,
      proposal("c4.nearest"), // e3 replaced
      second("e4", "c5"),
    );
    const result = cardOutcomes(events);
    const budget = must(
      events[0]?.type === "run_started" ? events[0].contract.budget.max_approvals : null,
      "max_approvals",
    );
    expect([...result.byEndorsementId].map(([id, outcome]) => [id, outcome.kind])).toEqual([
      ["e1", "approved"],
      ["e2", "closed"],
      ["e3", "replaced"],
      ["e4", "open"],
    ]);
    expect([...result.remainingBefore.values()]).toEqual([
      budget,
      Math.max(budget - 1, 0),
      Math.max(budget - 1, 0),
      Math.max(budget - 1, 0),
    ]);
  });

  it("approvals left never go below zero", () => {
    const request = (id: string, call: string): Event => ({
      ...REQUEST,
      endorsement: { ...REQUEST.endorsement, endorsement_id: id, call_id: call },
    });
    const approvals: Event[] = [];
    for (let index = 0; index < 12; index += 1) {
      approvals.push(request(`x${index}`, `k${index}`), decision("ALLOW", `k${index}`));
    }
    const result = cardOutcomes(after(...approvals));
    expect(Math.min(...[...result.remainingBefore.values()].map((n) => n ?? 0))).toBe(0);
  });

  it("is unknown before run_started", () => {
    const withoutStart = toRequest.slice(1);
    expect(cardOutcomes(withoutStart).remainingBefore.get(CARD)).toBeNull();
  });

  it("depends only on the order of the events, however they arrive [I6]", () => {
    const full = after(LABELED, proposal(`${CALL}.nearest`), decision("ALLOW", `${CALL}.nearest`));
    // Fed one event at a time (as a live stream is), the answer is open until the proposal and
    // then never changes: no later event can undo an outcome.
    const kinds = full.slice(toRequest.length - 1).map((_, step) => {
      const prefix = full.slice(0, toRequest.length + step);
      return outcomeOf(prefix).kind;
    });
    expect(kinds).toEqual(["open", "open", "replaced", "replaced"]);
    expect(cardOutcomes(full)).toEqual(cardOutcomes([...full]));
  });

  it("the golden NOTARY stream as recorded: the card is resolved as rejected", () => {
    expect(outcomeOf(golden)).toEqual({ kind: "rejected", resolvedSeq: 9 });
  });

  describe("endorsement_resolved (#302)", () => {
    function resolved(outcome: string, id = CARD): Event {
      const event = must(
        golden.find((e) => e.type === "endorsement_resolved"),
        "the golden resolution",
      );
      return { ...event, endorsement_id: id, outcome: outcome as typeof event.outcome };
    }

    it("names a rejection, a timeout and a cancel, which the old stream could not tell apart [I4]", () => {
      for (const kind of ["rejected", "timed_out", "cancelled"] as const) {
        const events = after(resolved(kind), ORACLE, FINISHED);
        expect(outcomeOf(events)).toEqual({ kind, resolvedSeq: 9 });
      }
    });

    it("approved is followed by the call's own decision: allowed or blocked [I4]", () => {
      expect(outcomeOf(after(resolved("approved"), decision("ALLOW")))).toEqual({
        kind: "approved",
        decisionSeq: 10,
      });
      expect(
        outcomeOf(
          after(resolved("approved"), decision("BLOCK", CALL, "BUDGET_APPROVALS_EXHAUSTED")),
        ),
      ).toEqual({ kind: "blocked", decisionSeq: 10, code: "BUDGET_APPROVALS_EXHAUSTED" });
    });

    it("approved is already approved before the decision arrives [I4]", () => {
      expect(outcomeOf(after(resolved("approved")))).toEqual({ kind: "approved", decisionSeq: 9 });
    });

    it("replaced finds the new call past the value that was labeled [I2]", () => {
      const events = after(resolved("replaced"), LABELED, proposal(`${CALL}.nearest`));
      expect(outcomeOf(events)).toEqual({ kind: "replaced", proposalSeq: 11 });
      expect(outcomeOf(after(resolved("replaced")))).toEqual({ kind: "replaced", proposalSeq: 9 });
    });

    it("a resolution of another card is not this card's outcome", () => {
      const events = after(resolved("approved", "e9"), ORACLE);
      expect(outcomeOf(events)).toEqual({ kind: "closed", nextSeq: 9 });
    });

    it("an approved card is counted against the budget; the others are not", () => {
      const approvedThenRejected = after(resolved("approved"), decision("ALLOW"));
      expect(cardOutcomes(approvedThenRejected).remainingBefore.get(CARD)).toBe(
        cardOutcomes(toRequest).remainingBefore.get(CARD),
      );
    });
  });
});
