import type { OracleResult } from "@notary/schema";
import { describe, expect, it } from "vitest";

import { goalLights, laneLabel } from "../src/goal-lights";
import type { LightState } from "../src/goal-lights";

function oracle(attacker: boolean, user: boolean): OracleResult {
  return { attacker_goal_reached: attacker, user_goal_achieved: user, invariants: [] };
}

describe("goalLights", () => {
  it("covers the whole truth table [A3]", () => {
    for (const finished of [false, true]) {
      for (const unresolvedEndorsements of [0, 1]) {
        const context = { finished, unresolvedEndorsements };
        for (const attacker of [true, false]) {
          for (const achieved of [true, false]) {
            const expectedUser: LightState = achieved
              ? "good"
              : finished && unresolvedEndorsements === 0
                ? "bad"
                : "pending";
            const expectedAttacker: LightState = attacker ? "bad" : "good";
            expect(goalLights(oracle(attacker, achieved), context)).toEqual({
              user: expectedUser,
              attacker: expectedAttacker,
            });
          }
        }
        expect(goalLights(null, context)).toEqual({ user: "pending", attacker: "pending" });
      }
    }
  });

  it("without a context a missed user goal is pending [A3]", () => {
    expect(goalLights(oracle(true, false))).toEqual({ user: "pending", attacker: "bad" });
    expect(goalLights(oracle(false, true))).toEqual({ user: "good", attacker: "good" });
    expect(goalLights(null)).toEqual({ user: "pending", attacker: "pending" });
  });
});

describe("laneLabel", () => {
  it("names each lane and ignores the classifier name [I6]", () => {
    expect(laneLabel("notary", null)).toBe("NOTARY");
    expect(laneLabel("undefended", null)).toBe("Undefended");
    expect(laneLabel("classifier", null)).toBe("Classifier-only (stand-in)");
    expect(laneLabel("classifier", "some-model")).toBe("Classifier-only (stand-in)");
    expect(laneLabel(null, null)).toBe("");
  });
});
