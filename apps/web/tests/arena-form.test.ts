import type { ArenaResult } from "@notary/client";
import { describe, expect, it } from "vitest";

import {
  DEFAULT_ARENA_FORM,
  buildArenaCommand,
  chartSeries,
  laneTotals,
  roundText,
  totalsText,
} from "@/lib/arena-form";
import type { ArenaForm } from "@/lib/arena-form";

import { fixture } from "./playground-fixtures";

const arena = fixture("arena.seed0").body as ArenaResult;
const [classifier, notary] = arena.lanes;
if (classifier === undefined || notary === undefined) throw new Error("fixture changed");

function errorOf(change: Partial<ArenaForm>): string | null {
  const built = buildArenaCommand({ ...DEFAULT_ARENA_FORM, ...change });
  return built.ok ? null : built.error;
}

describe("arena form", () => {
  it("buildArenaCommand success", () => {
    expect(buildArenaCommand(DEFAULT_ARENA_FORM)).toEqual({
      ok: true,
      command: {
        type: "arena_start",
        scenario: "poisoned_bill",
        rounds: 5,
        lanes: ["undefended", "classifier", "notary"],
        seed: 0,
      },
    });
    const reordered = buildArenaCommand({
      ...DEFAULT_ARENA_FORM,
      lanes: ["notary", "classifier", "notary"],
    });
    expect(reordered.ok && reordered.command.lanes).toEqual(["classifier", "notary"]);
    const typed = buildArenaCommand({ ...DEFAULT_ARENA_FORM, rounds: " 10 ", seed: "7" });
    expect(typed.ok && [typed.command.rounds, typed.command.seed]).toEqual([10, 7]);
  });

  it("buildArenaCommand errors in order", () => {
    expect(errorOf({ rounds: "x" })).toBe("Rounds must be a whole number");
    expect(errorOf({ rounds: "" })).toBe("Rounds must be a whole number");
    expect(errorOf({ rounds: "2.5" })).toBe("Rounds must be a whole number");
    expect(errorOf({ rounds: "0" })).toBe("Rounds must be between 1 and 10");
    expect(errorOf({ rounds: "11" })).toBe("Rounds must be between 1 and 10");
    expect(errorOf({ seed: "-1" })).toBe("Seed must be a whole number, 0 or more");
    expect(errorOf({ seed: "1.5" })).toBe("Seed must be a whole number, 0 or more");
    expect(errorOf({ lanes: [] })).toBe("Pick at least one lane");
    expect(errorOf({ rounds: "x", seed: "-1", lanes: [] })).toBe("Rounds must be a whole number");
    expect(errorOf({ seed: "-1", lanes: [] })).toBe("Seed must be a whole number, 0 or more");
  });

  it("chartSeries [A3]", () => {
    const series = chartSeries(arena.lanes);
    expect(series.map((line) => line.label)).toEqual(["Classifier-only (stand-in)", "NOTARY"]);
    expect(series[0]?.rounds).toEqual([
      { round: 1, cumulativeSuccesses: 1 },
      { round: 2, cumulativeSuccesses: 2 },
      { round: 3, cumulativeSuccesses: 3 },
    ]);
    expect(series[1]?.rounds).toEqual([
      { round: 1, cumulativeSuccesses: 0 },
      { round: 2, cumulativeSuccesses: 0 },
      { round: 3, cumulativeSuccesses: 0 },
    ]);
  });

  it("roundText", () => {
    const [first] = classifier.rounds;
    if (first === undefined) throw new Error("fixture changed");
    expect(roundText(first)).toBe("Round 1: email, 34 characters, goal reached");
    expect(roundText({ ...first, attacker_goal_reached: false })).toMatch(/goal not reached$/);
    expect(
      roundText({
        round: 2,
        vector: null,
        payload_chars: 0,
        invalid_move: true,
        attacker_goal_reached: false,
        cumulative_successes: 0,
      }),
    ).toBe("Round 2: invalid move");
  });

  it("laneTotals", () => {
    expect(laneTotals(classifier)).toEqual({ rounds: 3, successes: 3, invalid: 0 });
    expect(laneTotals(notary)).toEqual({ rounds: 3, successes: 0, invalid: 0 });
    const [first, second] = notary.rounds;
    if (first === undefined || second === undefined) throw new Error("fixture changed");
    const withInvalid = {
      ...notary,
      rounds: [first, { ...second, invalid_move: true, vector: null, payload_chars: 0 }],
    };
    expect(laneTotals(withInvalid)).toEqual({ rounds: 2, successes: 0, invalid: 1 });
    expect(totalsText(withInvalid)).toBe("NOTARY: 0 of 2 rounds reached the goal, 1 invalid");
  });

  it("totalsText [A3]", () => {
    expect(totalsText(classifier)).toBe(
      "Classifier-only (stand-in): 3 of 3 rounds reached the goal",
    );
    expect(totalsText(notary)).toBe("NOTARY: 0 of 3 rounds reached the goal");
  });
});
