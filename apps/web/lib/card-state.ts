import type { CardOutcome, CardState } from "@notary/ui";

/** What the user clicked on a card. */
export type Decision = "approve" | "reject" | "use_nearest";

/**
 * The state a card is shown in. The stream decides whether a card is still open and how it ended
 * (`outcome`, from `cardOutcomes`); the click is the only thing the stream cannot know, and it
 * tells a rejection from a timeout.
 *
 * - open: pending, or sending once the user clicked; a socket closed with 4409 (`conflict`)
 *   turns an open card into "no longer open". Any other close leaves it as it was.
 * - approved, replaced, blocked: what the server did, whatever was clicked.
 * - closed (not approved): "rejected" when the user rejected it, otherwise "no longer open"
 *   (a timeout, a cancel, or an answer that did not take).
 */
export function shownState(
  outcome: CardOutcome,
  clicked: Decision | null,
  conflict: boolean,
): CardState {
  switch (outcome.kind) {
    case "approved":
      return "approved";
    case "replaced":
      return "replaced";
    case "blocked":
      return "blocked";
    case "closed":
      return clicked === "reject" ? "rejected" : "conflict";
    case "open":
      if (conflict) return "conflict";
      return clicked === null ? "pending" : "sending";
  }
}
