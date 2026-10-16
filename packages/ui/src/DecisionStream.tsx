import type { Event } from "@notary/schema";

import { describeEvent } from "./describe-event";

export interface DecisionStreamProps {
  events: readonly Event[];
}

export function DecisionStream({ events }: DecisionStreamProps) {
  if (events.length === 0) {
    return <p className="text-sm text-neutral-500">Waiting for events…</p>;
  }
  return (
    <ol className="space-y-1 font-mono text-sm" aria-label="Decision stream">
      {events.map((event) => (
        <li key={event.seq} data-event-type={event.type} className="flex gap-2">
          <span className="text-neutral-400">{String(event.seq).padStart(3, "0")}</span>
          <span className="font-semibold">{event.type}</span>
          <span>{describeEvent(event)}</span>
        </li>
      ))}
    </ol>
  );
}
