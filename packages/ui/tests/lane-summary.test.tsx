import type { Decision } from "@notary/schema";
import { describe, expect, it } from "vitest";

import { laneLabel } from "../src/goal-lights";
import { laneHeading, summarizeLane } from "../src/lane-summary";
import type { RunView } from "../src/run-view";
import { emptyRunView } from "../src/run-view";
import { must, viewOf } from "./golden";

const PAYMENT = "paid 120.00 EUR to DE00ATTACKER0000000001";

function deepFreeze<T>(input: T): T {
  if (input !== null && typeof input === "object" && !Object.isFrozen(input)) {
    Object.freeze(input);
    for (const key of Object.keys(input)) deepFreeze((input as Record<string, unknown>)[key]);
  }
  return input;
}

describe("laneHeading", () => {
  it("uses the existing labels, and adds the filter name for the classifier lane [A3]", () => {
    expect(laneHeading("undefended", null)).toBe(laneLabel("undefended", null));
    expect(laneHeading("notary", null)).toBe("NOTARY");
    expect(laneHeading("undefended", null)).toBe("Undefended");
    expect(laneHeading("classifier", null)).toBe("Classifier-only (stand-in)");
    expect(laneHeading("classifier", "")).toBe("Classifier-only (stand-in)");
    expect(laneHeading("classifier", "keyword filter")).toBe(
      "Classifier-only (stand-in: keyword filter)",
    );
    expect(laneHeading("notary", "ignored")).toBe("NOTARY");
  });
});

describe("summarizeLane on the golden streams", () => {
  it("summarizes the undefended lane [A3]", () => {
    const s = summarizeLane(viewOf("poisoned_bill.undefended"));
    expect(s).toMatchObject({
      lane: "undefended",
      label: "Undefended",
      calls: 2,
      allowed: 0,
      escalated: 0,
      blocked: 0,
      executed: 2,
      attackerGoal: "bad",
      userGoal: "bad",
      outcome: "completed",
    });
    expect(s.effects).toEqual(["read 2 messages", PAYMENT]);
  });

  it("summarizes the classifier lane with the stand-in label [A3]", () => {
    const view = viewOf("poisoned_bill.classifier");
    const s = summarizeLane(view);
    expect(s.effects).toEqual(summarizeLane(viewOf("poisoned_bill.undefended")).effects);
    expect(s.attackerGoal).toBe("bad");
    expect(s.label).toContain("stand-in");
    expect(s.label).toBe(laneHeading("classifier", view.classifier));
    expect(view.classifier).not.toBeNull();
  });

  it("summarizes the NOTARY lane [A3]", () => {
    const s = summarizeLane(viewOf("poisoned_bill.notary"));
    expect(s).toMatchObject({
      lane: "notary",
      label: "NOTARY",
      calls: 2,
      allowed: 1,
      escalated: 1,
      blocked: 0,
      executed: 1,
      attackerGoal: "good",
      userGoal: "pending",
      outcome: "blocked",
    });
    expect(s.effects).toEqual(["read 2 messages"]);
  });

  it("summarizes the legitimate NOTARY lane [I1]", () => {
    const s = summarizeLane(viewOf("legitimate_bill.notary"));
    expect(s).toMatchObject({ allowed: 2, executed: 2, attackerGoal: "good", userGoal: "good" });
    expect(s.effects).toHaveLength(2);
  });

  it("summarizes an empty view without a label and with pending lights [I6]", () => {
    expect(summarizeLane(emptyRunView)).toEqual({
      lane: null,
      label: "",
      calls: 0,
      allowed: 0,
      escalated: 0,
      blocked: 0,
      executed: 0,
      effects: [],
      attackerGoal: "pending",
      userGoal: "pending",
      outcome: null,
    });
  });
});

describe("summarizeLane details", () => {
  it("counts the latest decision after an approval [A3]", () => {
    const base = viewOf("poisoned_bill.notary");
    const escalate = must(base.calls[1]?.decision, "the escalation");
    const allow: Decision = { verdict: "ALLOW", reasons: [], diff_card: null };
    const view: RunView = {
      ...base,
      calls: base.calls.map((call) =>
        call.callId === "c2"
          ? { ...call, decision: allow, decisionHistory: [{ decision: escalate, seq: 50 }] }
          : call,
      ),
    };
    expect(summarizeLane(view)).toMatchObject({ allowed: 2, escalated: 0, blocked: 0 });
  });

  it("counts a blocked call and leaves undecided calls out of every verdict [A4]", () => {
    const base = viewOf("poisoned_bill.notary");
    const block: Decision = { verdict: "BLOCK", reasons: [], diff_card: null };
    const view: RunView = {
      ...base,
      calls: base.calls.map((call) =>
        call.callId === "c1" ? { ...call, decision: null } : { ...call, decision: block },
      ),
    };
    expect(summarizeLane(view)).toMatchObject({ allowed: 0, escalated: 0, blocked: 1 });
  });

  it("orders the effects by proposed seq then call id, not by input order [I6]", () => {
    const base = viewOf("poisoned_bill.undefended");
    const view: RunView = { ...base, calls: [...base.calls].reverse() };
    expect(summarizeLane(view).effects).toEqual(["read 2 messages", PAYMENT]);
  });

  it("is pure, and the endorsement override changes only the user light [I6]", () => {
    const view = deepFreeze(viewOf("poisoned_bill.notary"));
    const first = summarizeLane(view);
    expect(summarizeLane(view)).toEqual(first);
    expect(first.effects).not.toBe(summarizeLane(view).effects);

    const settled = summarizeLane(view, { unresolvedEndorsements: 0 });
    expect(settled.userGoal).toBe("bad");
    expect({ ...settled, userGoal: first.userGoal }).toEqual(first);
  });
});
