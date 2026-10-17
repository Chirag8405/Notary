"use client";

import { DecisionStream, OraclePanel, ProvenanceGraph, ReplayPlayer, viewAt } from "@notary/ui";
import type { Event } from "@notary/schema";
import { useMemo, useState } from "react";

import { Card, CardContent, CardHeader } from "@/components/ui/card";

export interface RunResultProps {
  title: string;
  /** The validated events of ONE run. */
  events: readonly Event[];
}

/**
 * One recorded run: oracle lights, decision stream and provenance graph, folded from its events,
 * with a replay player to step through them. It opens on the whole run (the position is the
 * number of events shown); a new run opens on its end as well.
 */
export function RunResult({ title, events }: RunResultProps) {
  // The position belongs to one `events` array: another run starts again from its end (`null`).
  const [replay, setReplay] = useState<{
    events: readonly Event[];
    position: number | null;
  }>({ events, position: null });
  const position = replay.events === events ? (replay.position ?? events.length) : events.length;
  const view = useMemo(() => viewAt(events, position), [events, position]);
  return (
    <Card className="text-sm" aria-label={title}>
      <CardHeader>
        <h3 className="text-sm font-semibold">{title}</h3>
      </CardHeader>
      <CardContent className="space-y-4">
        {events.length === 0 ? (
          <p>No events</p>
        ) : (
          <>
            <ReplayPlayer
              events={events}
              position={position}
              onPositionChange={(next) => {
                setReplay({ events, position: next });
              }}
              label={`${title}: replay`}
            />
            <OraclePanel view={view} />
            <DecisionStream view={view} />
            <ProvenanceGraph view={view} />
          </>
        )}
      </CardContent>
    </Card>
  );
}
