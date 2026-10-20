import { describe, expect, it } from "vitest";

import {
  GUIDED_STEPS,
  attemptOutcome,
  laneOutcome,
  originText,
  stepIndex,
  summarizeOutcome,
} from "@/lib/guided";

const done = { outcome: "completed", summary: "", seq: 9 } as const;
const oracle = (attacker: boolean, user: boolean) => ({
  attacker_goal_reached: attacker,
  user_goal_achieved: user,
  invariants: [],
});

describe("guided steps", () => {
  it("has four steps, the last one without a run", () => {
    expect(GUIDED_STEPS.map((step) => step.id)).toEqual(["attack", "pause", "normal", "try"]);
    expect(GUIDED_STEPS[3]?.scenario).toBeNull();
  });

  it("falls back to the first step for an unknown id", () => {
    expect(stepIndex("normal")).toBe(2);
    expect(stepIndex("nope")).toBe(0);
    expect(stepIndex(null)).toBe(0);
  });
});

describe("summarizeOutcome", () => {
  const none = { unresolved: 0, rejected: 0 };

  it("waits while a card is unanswered", () => {
    expect(
      summarizeOutcome({ oracle: null, finished: null }, { ...none, unresolved: 1 }).tone,
    ).toBe("warn");
  });

  it("is idle until the run has finished", () => {
    expect(summarizeOutcome({ oracle: null, finished: null }, none).tone).toBe("idle");
    expect(summarizeOutcome({ oracle: oracle(false, true), finished: null }, none).tone).toBe(
      "idle",
    );
  });

  it("says the attacker won when the oracle says so, whatever the user did", () => {
    const outcome = summarizeOutcome({ oracle: oracle(true, false), finished: done }, none);
    expect(outcome.tone).toBe("danger");
  });

  it("says the bill was paid safely when only the user goal was reached", () => {
    expect(summarizeOutcome({ oracle: oracle(false, true), finished: done }, none).tone).toBe(
      "safe",
    );
  });

  it("calls a rejection safe, and an unfinished task a warning", () => {
    const view = { oracle: oracle(false, false), finished: done };
    expect(summarizeOutcome(view, { unresolved: 0, rejected: 1 }).tone).toBe("safe");
    expect(summarizeOutcome(view, none).tone).toBe("warn");
  });
});

describe("originText", () => {
  it("names where a value came from", () => {
    expect(originText({ kind: "user" })).toBe("You typed it");
    expect(originText({ kind: "ledger" })).toBe("From your trusted list");
  });
});

describe("laneOutcome and attemptOutcome", () => {
  it("reads a lane from the oracle's booleans", () => {
    expect(laneOutcome(null, null).tone).toBe("idle");
    expect(laneOutcome(true, false).tone).toBe("danger");
    expect(laneOutcome(false, true).title).toBe("Attack stopped, task done");
    expect(laneOutcome(false, false).title).toBe("Attack stopped");
  });

  it("calls a blocked or refused attempt safe and an executed one a warning", () => {
    expect(attemptOutcome("blocked").tone).toBe("safe");
    expect(attemptOutcome("escalated").tone).toBe("safe");
    expect(attemptOutcome("executed").tone).toBe("warn");
    expect(attemptOutcome("halted").tone).toBe("idle");
  });
});
