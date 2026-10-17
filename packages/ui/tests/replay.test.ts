import { describe, expect, it } from "vitest";

import { clampPosition, positionLabel, stepPosition, viewAt } from "../src/replay";
import { emptyRunView, foldEvents } from "../src/run-view";
import { load, must } from "./golden";

const events = load("poisoned_bill.notary");

/** The number of events shown once the first event matching `match` is applied. */
function positionOf(match: (event: (typeof events)[number]) => boolean): number {
  return must(events.findIndex(match) + 1 || null, "event in the golden stream");
}

describe("replay helpers", () => {
  it("clampPosition table", () => {
    expect(clampPosition(5, 20)).toBe(5);
    expect(clampPosition(-3, 20)).toBe(0);
    expect(clampPosition(99, 20)).toBe(20);
    expect(clampPosition(2.9, 20)).toBe(2);
    expect(clampPosition(NaN, 20)).toBe(0);
    expect(clampPosition(Infinity, 20)).toBe(20);
    expect(clampPosition(-Infinity, 20)).toBe(0);
    expect(clampPosition(4, 0)).toBe(0);
    expect(clampPosition(-0.5, 20)).toBe(0);
    expect(clampPosition(4, -3)).toBe(0);
  });

  it("stepPosition table", () => {
    expect(stepPosition(0, 20, "previous")).toBe(0);
    expect(stepPosition(20, 20, "next")).toBe(20);
    expect(stepPosition(7, 20, "first")).toBe(0);
    expect(stepPosition(7, 20, "last")).toBe(20);
    expect(stepPosition(7, 20, "next")).toBe(8);
    expect(stepPosition(7, 20, "previous")).toBe(6);
    expect(stepPosition(99, 20, "previous")).toBe(19);
    expect(stepPosition(-5, 20, "next")).toBe(1);
  });

  it("positionLabel strings", () => {
    expect(positionLabel(0, 0)).toBe("No events");
    expect(positionLabel(0, 20)).toBe("Start (0 of 20)");
    expect(positionLabel(7, 20)).toBe("Event 7 of 20");
    expect(positionLabel(20, 20)).toBe("Event 20 of 20");
    expect(positionLabel(99, 20)).toBe("Event 20 of 20");
  });

  it("viewAt equals foldEvents on a prefix [A3]", () => {
    const before = [...events];
    for (let n = 0; n <= events.length; n += 1) {
      expect(viewAt(events, n)).toEqual(foldEvents(events.slice(0, n)));
    }
    expect(viewAt(events, 0)).toEqual(emptyRunView); // a fresh copy: the fold never shares state
    expect(viewAt(events, events.length)).toEqual(foldEvents(events));
    expect(viewAt(events, events.length + 10)).toEqual(foldEvents(events));
    expect(events).toEqual(before);
  });

  it("ESCALATE appears at its event [A3]", () => {
    const k = positionOf(
      (event) => event.type === "decision_made" && event.decision.verdict === "ESCALATE",
    );
    const after = viewAt(events, k).calls.find((call) => call.decision?.verdict === "ESCALATE");
    const callId = must(after, "escalated call").callId;
    const earlier = must(
      viewAt(events, k - 1).calls.find((call) => call.callId === callId),
      "the call one position earlier",
    );
    expect(earlier.decision).toBeNull();
  });

  it("oracle light flips only at the end [A3]", () => {
    const k = positionOf((event) => event.type === "oracle_updated");
    for (let n = 0; n < k; n += 1) expect(viewAt(events, n).oracle).toBeNull();
    for (let n = k; n <= events.length; n += 1) {
      expect(must(viewAt(events, n).oracle, "oracle").attacker_goal_reached).toBe(false);
    }
  });
});
