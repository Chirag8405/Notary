"use client";

import { useRunStream } from "@notary/client/react";
import type { WebSocketFactory } from "@notary/client";
import type { IntentContract, OracleResult } from "@notary/schema";
import {
  ContractPanel,
  DecisionStream,
  OracleLights,
  ProvenanceGraph,
  foldEvents,
} from "@notary/ui";
import { useMemo } from "react";

import { Card, CardTitle } from "@/components/ui/card";

export interface XRayViewProps {
  apiUrl: string;
  scenario: string;
  webSocket?: WebSocketFactory;
}

export function XRayView({ apiUrl, scenario, webSocket }: XRayViewProps) {
  const stream = useRunStream(apiUrl, scenario, webSocket);
  const view = useMemo(() => foldEvents(stream.events), [stream.events]);

  let contract: IntentContract | null = null;
  let oracle: OracleResult | null = null;
  for (const event of stream.events) {
    if (event.type === "run_started") contract = event.contract;
    if (event.type === "oracle_updated") oracle = event.result;
  }

  return (
    <main className="mx-auto grid max-w-5xl gap-4 p-6 md:grid-cols-2">
      <h1 className="text-xl font-bold md:col-span-2">
        Trust X-ray <span className="text-sm font-normal text-neutral-500">({stream.status})</span>
      </h1>
      {stream.status === "error" ? (
        <p role="alert" className="text-red-600 md:col-span-2">
          {stream.error.message}
        </p>
      ) : null}
      <Card>
        <CardTitle>Decision stream</CardTitle>
        <DecisionStream events={stream.events} />
      </Card>
      <Card>
        <CardTitle>Provenance graph</CardTitle>
        <ProvenanceGraph view={view} />
      </Card>
      <Card>
        <CardTitle>Intent contract</CardTitle>
        <ContractPanel contract={contract} />
      </Card>
      <Card>
        <CardTitle>Oracle</CardTitle>
        <OracleLights result={oracle} />
      </Card>
    </main>
  );
}
