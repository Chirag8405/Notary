import { goalLights, laneLabel } from "./goal-lights";
import type { LightState } from "./goal-lights";
import type { LaneName, RunView } from "./run-view";

/**
 * What one lane of the three-lane view shows, folded from that lane's RunView. Pure and
 * deterministic: no React, clock or randomness, and the view is never mutated.
 */

export type LaneStatus = "waiting" | "running" | "finished" | "error";

export interface LaneInput {
  lane: LaneName;
  view: RunView;
  status: LaneStatus;
  error?: string;
}

export interface LaneSummary {
  lane: LaneName | null;
  /** "" until the stream has said which lane it is. */
  label: string;
  calls: number;
  allowed: number;
  escalated: number;
  blocked: number;
  executed: number;
  /** Executed summaries in call order. */
  effects: readonly string[];
  attackerGoal: LightState;
  userGoal: LightState;
  outcome: "completed" | "blocked" | "error" | null;
}

/**
 * The heading of a lane. The classifier lane always says "stand-in", and adds the filter's name
 * when the stream gave one.
 */
export function laneHeading(lane: LaneName, classifier: string | null): string {
  if (lane === "classifier" && classifier !== null && classifier !== "") {
    return `Classifier-only (stand-in: ${classifier})`;
  }
  return laneLabel(lane, classifier);
}

function byText(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

/**
 * Count calls by their LATEST decision (an approved escalation counts once, as allowed). The goal
 * lights follow the oracle panel: `unresolvedEndorsements` defaults to every endorsement in the
 * view, because the stream never reports one as resolved.
 */
export function summarizeLane(
  view: RunView,
  options?: { unresolvedEndorsements?: number },
): LaneSummary {
  const calls = [...view.calls].sort(
    (a, b) => a.proposedSeq - b.proposedSeq || byText(a.callId, b.callId),
  );
  const verdicts = calls.map((call) => (call.decision === null ? null : call.decision.verdict));
  const lights = goalLights(view.oracle, {
    finished: view.finished !== null,
    unresolvedEndorsements: options?.unresolvedEndorsements ?? view.endorsements.length,
  });
  return {
    lane: view.lane,
    label: view.lane === null ? "" : laneHeading(view.lane, view.classifier),
    calls: calls.length,
    allowed: verdicts.filter((verdict) => verdict === "ALLOW").length,
    escalated: verdicts.filter((verdict) => verdict === "ESCALATE").length,
    blocked: verdicts.filter((verdict) => verdict === "BLOCK").length,
    executed: calls.filter((call) => call.executed !== null).length,
    effects: calls.flatMap((call) => (call.executed === null ? [] : [call.executed.summary])),
    attackerGoal: lights.attacker,
    userGoal: lights.user,
    outcome: view.finished === null ? null : view.finished.outcome,
  };
}
