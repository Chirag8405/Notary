"use client";

import { DecisionStream, OraclePanel, ProvenanceGraph, foldEvents } from "@notary/ui";
import type { Event } from "@notary/schema";
import { useMemo } from "react";

import { Card, CardContent, CardHeader } from "@/components/ui/card";

export interface RunResultProps {
  title: string;
  /** The validated events of ONE run. */
  events: readonly Event[];
}

/** One recorded run: oracle lights, decision stream and provenance graph, folded from its events. */
export function RunResult({ title, events }: RunResultProps) {
  const view = useMemo(() => foldEvents(events), [events]);
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
            <OraclePanel view={view} />
            <DecisionStream view={view} />
            <ProvenanceGraph view={view} />
          </>
        )}
      </CardContent>
    </Card>
  );
}
