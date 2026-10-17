import type { ArenaLane, ArenaRound, ArenaStartBody } from "@notary/client";
import { laneLabel } from "@notary/ui";
import type { AsrSeriesInput } from "@notary/ui";

/**
 * Pure helpers of the "Attacker arena" panel: the form's defaults, how a form becomes a command,
 * and how the server's rounds become chart series and text. No React, no I/O, no clock or
 * randomness.
 */

export const ARENA_SCENARIO = "poisoned_bill";
export const ARENA_LANES = ["undefended", "classifier", "notary"] as const;
export type ArenaLaneName = (typeof ARENA_LANES)[number];

/** The server's default cap (`NOTARY_ARENA_MAX_ROUNDS`); the UI does not raise it on its own. */
export const MAX_ROUNDS_UI = 10;

/** Numbers are kept as typed text until the form is built. */
export interface ArenaForm {
  rounds: string;
  seed: string;
  lanes: readonly ArenaLaneName[];
}

export const DEFAULT_ARENA_FORM: ArenaForm = {
  rounds: "5",
  seed: "0",
  lanes: ["undefended", "classifier", "notary"],
};

export type ArenaBuild = { ok: true; command: ArenaStartBody } | { ok: false; error: string };

const WHOLE_NUMBER = /^\d+$/;

/** The command for a form, or the first failing rule. */
export function buildArenaCommand(form: ArenaForm): ArenaBuild {
  const rounds = form.rounds.trim();
  if (!WHOLE_NUMBER.test(rounds)) return { ok: false, error: "Rounds must be a whole number" };
  const roundCount = Number(rounds);
  if (roundCount < 1 || roundCount > MAX_ROUNDS_UI) {
    return { ok: false, error: `Rounds must be between 1 and ${MAX_ROUNDS_UI}` };
  }
  const seed = form.seed.trim();
  if (!WHOLE_NUMBER.test(seed)) {
    return { ok: false, error: "Seed must be a whole number, 0 or more" };
  }
  const lanes = ARENA_LANES.filter((lane) => form.lanes.includes(lane));
  if (lanes.length === 0) return { ok: false, error: "Pick at least one lane" };
  return {
    ok: true,
    command: {
      type: "arena_start",
      scenario: ARENA_SCENARIO,
      rounds: roundCount,
      lanes,
      seed: Number(seed),
    },
  };
}

/** One series per lane in response order, labelled with the lane's exact label. */
export function chartSeries(lanes: readonly ArenaLane[]): readonly AsrSeriesInput[] {
  return lanes.map((lane) => ({
    label: laneLabel(lane.lane, null),
    rounds: lane.rounds.map((round) => ({
      round: round.round,
      cumulativeSuccesses: round.cumulative_successes,
    })),
  }));
}

/** One line per round: vector and payload length only (the response carries no payload text). */
export function roundText(round: ArenaRound): string {
  if (round.invalid_move) return `Round ${round.round}: invalid move`;
  const outcome = round.attacker_goal_reached ? "goal reached" : "goal not reached";
  return `Round ${round.round}: ${round.vector ?? "none"}, ${round.payload_chars} characters, ${outcome}`;
}

export function laneTotals(lane: ArenaLane): {
  rounds: number;
  successes: number;
  invalid: number;
} {
  return {
    rounds: lane.rounds.length,
    successes: lane.rounds.filter((round) => round.attacker_goal_reached).length,
    invalid: lane.rounds.filter((round) => round.invalid_move).length,
  };
}

/** "NOTARY: 0 of 3 rounds reached the goal", plus ", 1 invalid" when a round was invalid. */
export function totalsText(lane: ArenaLane): string {
  const totals = laneTotals(lane);
  const base = `${laneLabel(lane.lane, null)}: ${totals.successes} of ${totals.rounds} rounds reached the goal`;
  return totals.invalid > 0 ? `${base}, ${totals.invalid} invalid` : base;
}
