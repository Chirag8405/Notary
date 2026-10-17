"use client";

import { createRestClient, getPendingEndorsements } from "@notary/client";
import type { RunMode, WebSocketFactory } from "@notary/client";
import { useRunStream } from "@notary/client/react";
import {
  ContentInspector,
  ContractPanel,
  DecisionStream,
  OraclePanel,
  ProvenanceGraph,
  ThreeLaneView,
  emptyRunView,
  foldEvents,
  laneLabel,
} from "@notary/ui";
import type { LaneInput, LaneName } from "@notary/ui";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { AnchorFooter } from "@/components/anchor-footer";
import { EffectsList } from "@/components/effects-list";
import { EndorsementPanel } from "@/components/endorsement-panel";
import { RunControls } from "@/components/run-controls";
import { Card, CardContent } from "@/components/ui/card";
import {
  DEFAULT_MODE,
  callIdForSelection,
  describeStreamError,
  scenarioLanes,
  selectionFromChip,
  settleSelection,
  toLaneStatus,
  valueIdForSelection,
  xrayUrl,
} from "@/lib/x-ray-state";
import type { Selection, ViewMode } from "@/lib/x-ray-state";

export interface XRayViewProps {
  apiUrl: string;
  scenario: string;
  mode?: RunMode;
  initialViewMode?: ViewMode;
  /** Test seam: the socket factory. */
  webSocket?: WebSocketFactory;
}

type Stream = ReturnType<typeof useRunStream>;

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <h2 className="px-4 text-sm font-medium">{title}</h2>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

/** One lane's input for the three-lane view, from a stream hook and its folded view. */
function laneInput(
  lane: LaneName,
  stream: Stream,
  view: LaneInput["view"],
  apiUrl: string,
): LaneInput {
  // A stream that says it belongs to another lane (the server's golden mode ignores the lane
  // parameter) must not be shown under this lane's name.
  if (view.lane !== null && view.lane !== lane) {
    return {
      lane,
      view: emptyRunView,
      status: "error",
      error: `The server sent the ${view.lane} stream for the ${lane} lane. Try another mode.`,
    };
  }
  const base = { lane, view, status: toLaneStatus(stream.status) };
  return stream.status === "error"
    ? { ...base, error: describeStreamError(stream.closeCode, stream.error.message, apiUrl) }
    : base;
}

/**
 * The baseline lanes of the three-lane view. The NOTARY lane comes in as a prop, folded from the
 * page's own stream, so toggling this view never opens a second NOTARY socket.
 */
function ThreeLaneContainer({
  apiUrl,
  scenario,
  mode,
  webSocket,
  notary,
}: {
  apiUrl: string;
  scenario: string;
  mode: RunMode;
  webSocket: WebSocketFactory | undefined;
  notary: LaneInput;
}) {
  const socket = webSocket === undefined ? {} : { webSocket };
  const undefended = useRunStream(apiUrl, scenario, { lane: "undefended", mode, ...socket });
  const classifier = useRunStream(apiUrl, scenario, { lane: "classifier", mode, ...socket });
  const undefendedView = useMemo(() => foldEvents(undefended.events), [undefended.events]);
  const classifierView = useMemo(() => foldEvents(classifier.events), [classifier.events]);

  const lanes = scenarioLanes(scenario).map((lane): LaneInput => {
    if (lane === "undefended") return laneInput(lane, undefended, undefendedView, apiUrl);
    if (lane === "classifier") return laneInput(lane, classifier, classifierView, apiUrl);
    return notary;
  });
  return <ThreeLaneView lanes={lanes} />;
}

/** One run: a single NOTARY stream folded once, and every region drawn from that view. */
function XRayRun({
  apiUrl,
  scenario,
  mode,
  viewMode,
  webSocket,
}: {
  apiUrl: string;
  scenario: string;
  mode: RunMode;
  viewMode: ViewMode;
  webSocket: WebSocketFactory | undefined;
}) {
  const stream = useRunStream(apiUrl, scenario, {
    lane: "notary",
    mode,
    ...(webSocket === undefined ? {} : { webSocket }),
  });
  const view = useMemo(() => foldEvents(stream.events), [stream.events]);
  const client = useMemo(() => createRestClient(apiUrl), [apiUrl]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [resolved, setResolved] = useState<ReadonlySet<string>>(() => new Set());

  const runId = view.runId;
  const fetchPending = useCallback(async () => {
    if (runId === null) return [];
    const list = await getPendingEndorsements(client, runId);
    return list.pending.map((item) => ({
      endorsement: item.endorsement,
      remaining_approvals: item.remaining_approvals,
    }));
  }, [client, runId]);
  const onResolvedChange = useCallback((next: ReadonlySet<string>) => {
    setResolved((previous) =>
      previous.size === next.size && [...next].every((id) => previous.has(id)) ? previous : next,
    );
  }, []);
  const toolByCallId = useMemo(
    () => Object.fromEntries(view.calls.map((call) => [call.callId, call.tool])),
    [view.calls],
  );

  const unresolved = view.endorsements.filter(
    (item) => !resolved.has(item.endorsement.endorsement_id),
  ).length;
  const notary: LaneInput = laneInput("notary", stream, view, apiUrl);

  return (
    <>
      <header>
        <h1 className="text-xl font-bold">
          Trust X-ray{" "}
          <span className="text-sm font-normal text-neutral-500">({stream.status})</span>{" "}
          <span className="text-sm font-normal text-neutral-500">{laneLabel("notary", null)}</span>
        </h1>
      </header>
      {stream.status === "error" ? (
        <div role="alert" className="text-red-700">
          {describeStreamError(stream.closeCode, stream.error.message, apiUrl)}
        </div>
      ) : null}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Contract">
          <ContractPanel contract={view.contract} />
        </Panel>
        <div className="space-y-4">
          <Panel title="Provenance graph">
            <ProvenanceGraph view={view} selectedId={selectedId} onSelect={setSelectedId} />
          </Panel>
          {runId !== null && view.endorsements.length > 0 ? (
            <EndorsementPanel
              runId={runId}
              endorsements={view.endorsements}
              send={stream.send}
              fetchPending={fetchPending}
              eventCount={view.lastSeq + 1}
              toolByCallId={toolByCallId}
              onResolvedChange={onResolvedChange}
              {...(stream.status === "error" && stream.closeCode !== undefined
                ? { closeCode: stream.closeCode }
                : {})}
            />
          ) : null}
          <Panel title="Content inspector">
            <ContentInspector view={view} valueId={valueIdForSelection(view, selectedId)} />
          </Panel>
        </div>
        <Panel title="Decision stream">
          <DecisionStream
            view={view}
            selectedCallId={callIdForSelection(view, selectedId)}
            onSelect={(target) => {
              setSelectedId(selectionFromChip(target).nodeId);
            }}
            resolvedEndorsements={resolved}
          />
        </Panel>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <Panel title="Oracle">
          <OraclePanel view={view} unresolvedEndorsements={unresolved} />
        </Panel>
        <Panel title="What changed">
          <EffectsList view={view} />
        </Panel>
      </div>
      {viewMode === "three-lane" ? (
        <ThreeLaneContainer
          apiUrl={apiUrl}
          scenario={scenario}
          mode={mode}
          webSocket={webSocket}
          notary={notary}
        />
      ) : null}
      <AnchorFooter client={client} runId={runId} finished={view.finished !== null} />
    </>
  );
}

/** The Trust X-ray: controls on top, then the regions of one run. */
export function XRayView({
  apiUrl,
  scenario: initialScenario,
  mode: initialMode = DEFAULT_MODE,
  initialViewMode = "single",
  webSocket,
}: XRayViewProps) {
  // Every choice goes through `settleSelection`, so a combination the server cannot serve (golden
  // for legitimate_bill or for the three-lane view) is never opened.
  const [initial] = useState(() =>
    settleSelection({ scenario: initialScenario, mode: initialMode, viewMode: initialViewMode }),
  );
  const [selection, setSelection] = useState(initial);
  const [runKey, setRunKey] = useState(0);

  // An address that asked for such a combination is corrected in the address bar too.
  useEffect(() => {
    if (initial.note !== null) window.history.replaceState(null, "", xrayUrl(initial));
  }, [initial]);

  const apply = (next: Selection) => {
    const settled = settleSelection(next);
    setSelection(settled);
    if (settled.scenario !== selection.scenario || settled.mode !== selection.mode) {
      setRunKey((key) => key + 1);
    }
    window.history.replaceState(null, "", xrayUrl(settled));
  };

  return (
    <main className="mx-auto max-w-7xl space-y-4 p-4 md:p-6">
      <RunControls
        apiUrl={apiUrl}
        scenario={selection.scenario}
        mode={selection.mode}
        viewMode={selection.viewMode}
        note={selection.note}
        onScenarioChange={(next) => {
          apply({ ...selection, scenario: next });
        }}
        onModeChange={(next) => {
          apply({ ...selection, mode: next });
        }}
        onViewModeChange={(next) => {
          apply({ ...selection, viewMode: next });
        }}
        onRunAgain={() => {
          setRunKey((key) => key + 1);
        }}
      />
      <XRayRun
        key={runKey}
        apiUrl={apiUrl}
        scenario={selection.scenario}
        mode={selection.mode}
        viewMode={selection.viewMode}
        webSocket={webSocket}
      />
    </main>
  );
}
