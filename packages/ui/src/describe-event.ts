import type { Event } from "@notary/schema";

/** One-line human summary of an event. Exhaustive: a new event type fails to compile here. */
export function describeEvent(event: Event): string {
  switch (event.type) {
    case "run_started":
      return `Run started: ${event.scenario} (${event.contract.user_intent})`;
    case "value_labeled":
      return `Value ${event.value.id} labeled ${event.value.label.integrity} (${event.value.label.origin.kind})`;
    case "call_proposed":
      return `Proposed ${event.proposal.tool}(${Object.keys(event.proposal.args).join(", ")})`;
    case "decision_made":
      return `${event.decision.verdict} for ${event.call_id}`;
    case "endorsement_requested":
      return `Endorsement ${event.endorsement.status} for ${event.endorsement.call_id}`;
    case "endorsement_resolved":
      return `Endorsement ${event.endorsement_id} ${event.outcome.replace("_", " ")}`;
    case "effect_executed":
      return `Executed ${event.tool}: ${event.summary}`;
    case "oracle_updated":
      return `Oracle: ${event.result.invariants.filter((i) => i.passed).length}/${event.result.invariants.length} invariants hold`;
    case "run_finished":
      return `Run ${event.outcome}: ${event.summary}`;
    default:
      return assertNever(event);
  }
}

function assertNever(value: never): never {
  throw new Error(`Unhandled event: ${JSON.stringify(value)}`);
}
