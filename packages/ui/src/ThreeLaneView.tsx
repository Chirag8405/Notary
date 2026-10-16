import type { Event } from "@notary/schema";

import { describeEvent } from "./describe-event";

export interface ThreeLaneViewProps {
  events: readonly Event[];
}

type Lane = "proposed" | "decided" | "executed";

function laneOf(event: Event): Lane | null {
  switch (event.type) {
    case "call_proposed":
      return "proposed";
    case "decision_made":
    case "endorsement_requested":
      return "decided";
    case "effect_executed":
      return "executed";
    default:
      return null;
  }
}

const LANES: readonly Lane[] = ["proposed", "decided", "executed"];

export function ThreeLaneView({ events }: ThreeLaneViewProps) {
  return (
    <div className="grid grid-cols-3 gap-4" aria-label="Three lanes">
      {LANES.map((lane) => (
        <div key={lane} data-lane={lane}>
          <h3 className="mb-1 text-xs font-semibold uppercase text-neutral-500">{lane}</h3>
          <ul className="space-y-1 text-sm">
            {events
              .filter((event) => laneOf(event) === lane)
              .map((event) => (
                <li key={event.seq}>{describeEvent(event)}</li>
              ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
