import type { OracleResult } from "@notary/schema";

import type { LaneName } from "./run-view";

/**
 * The two goal lights of the oracle panel, read from the oracle's two booleans. The UI never
 * recomputes a verdict: it only maps what the oracle reported to a light.
 */
export type LightState = "good" | "bad" | "pending" | "neutral";

export interface GoalLights {
  user: LightState;
  attacker: Exclude<LightState, "neutral">;
}

/**
 * Attacker: reached is bad, not reached is good. User: achieved is good; not achieved is pending
 * while the run is open or an endorsement is unresolved, and bad only once the run has finished
 * with nothing left to answer. When the user rejected an endorsement (`rejectedEndorsements`), that
 * settled "not achieved" is neutral: the bill was deliberately not paid, which is not a failure.
 * Without `context` a user goal that is not achieved is pending. No oracle yet gives two pending
 * lights.
 */
export function goalLights(
  oracle: OracleResult | null,
  context?: {
    finished: boolean;
    unresolvedEndorsements: number;
    rejectedEndorsements?: number;
  },
): GoalLights {
  if (oracle === null) return { user: "pending", attacker: "pending" };
  const attacker: GoalLights["attacker"] = oracle.attacker_goal_reached ? "bad" : "good";
  if (oracle.user_goal_achieved) return { user: "good", attacker };
  const settled = context !== undefined && context.finished && context.unresolvedEndorsements === 0;
  if (!settled) return { user: "pending", attacker };
  return { user: (context.rejectedEndorsements ?? 0) > 0 ? "neutral" : "bad", attacker };
}

/** The panel's lane name. The classifier name is accepted for the three-lane view and not shown. */
export const laneLabel: (lane: LaneName | null, classifier: string | null) => string = (lane) => {
  switch (lane) {
    case "notary":
      return "NOTARY";
    case "classifier":
      return "Classifier-only (stand-in)";
    case "undefended":
      return "Undefended";
    case null:
      return "";
  }
};
