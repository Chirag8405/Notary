"use client";

import { createRestClient } from "@notary/client";
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
import { DemoGuide, DemoStepNav } from "@/components/demo-steps";
import { RunControls } from "@/components/run-controls";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { DEMO_STEPS, activeStep } from "@/lib/demo-steps";
import {
  DEFAULT_MODE,
  callIdForSelection,
  MCP_NO_RUN,
  describeStreamError,
  scenarioLanes,
  selectMode,
  selectionFromChip,
  settleSelection,
  streamProblem,
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
  /** The demo step named in the address; tells step 2 from step 1 (same screen). */
  initialStep?: number;
  /** Test seam: the socket factory. */
  webSocket?: WebSocketFactory;
}

type Stream = ReturnType<typeof useRunStream>;

const STATUS_VARIANT = {
  connecting: "muted",
  open: "secondary",
  finished: "default",
  error: "destructive",
} as const;

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="text-sm">
      <CardHeader>
        <h2 className="text-sm font-semibold">{title}</h2>
      </CardHeader>
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
  onUseCassette,
  controls,
}: {
  apiUrl: string;
  scenario: string;
  mode: RunMode;
  viewMode: ViewMode;
  webSocket: WebSocketFactory | undefined;
  onUseCassette: () => void;
  controls: ReactNode;
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
  const [rejected, setRejected] = useState<ReadonlySet<string>>(() => new Set());

  const runId = view.runId;
  const onResolvedChange = useCallback((next: ReadonlySet<string>) => {
    setResolved((previous) =>
      previous.size === next.size && [...next].every((id) => previous.has(id)) ? previous : next,
    );
  }, []);
  const onRejectedChange = useCallback((next: ReadonlySet<string>) => {
    setRejected((previous) =>
      previous.size === next.size && [...next].every((id) => previous.has(id)) ? previous : next,
    );
  }, []);
  const toolByCallId = useMemo(
    () => Object.fromEntries(view.calls.map((call) => [call.callId, call.tool])),
    [view.calls],
  );

  // A run of the MCP proxy is followed while it is written: "live" until its `run_finished`.
  const following = mode === "mcp";
  const live =
    view.finished === null && (stream.status === "connecting" || stream.status === "open");

  const unresolved = view.endorsements.filter(
    (item) => !resolved.has(item.endorsement.endorsement_id),
  ).length;
  const notary: LaneInput = laneInput("notary", stream, view, apiUrl);
  const problem =
    stream.status === "error"
      ? streamProblem({
          closeCode: stream.closeCode,
          message: stream.error.message,
          apiUrl,
          mode,
        })
      : null;

  return (
    <>
      <header className="space-y-1">
        <p className="text-xs font-medium tracking-widest text-muted-foreground uppercase">
          NOTARY
        </p>
        <h1 className="flex flex-wrap items-center gap-3 text-2xl font-semibold tracking-tight">
          Trust X-ray
          <Badge variant={STATUS_VARIANT[stream.status]} data-status={stream.status}>
            {stream.status}
          </Badge>
          <Badge variant="outline">{laneLabel("notary", null)}</Badge>
          {following && live ? (
            <Badge variant="secondary" data-live>
              live
            </Badge>
          ) : null}
        </h1>
        {following ? (
          <p className="text-xs text-muted-foreground" data-mcp-run>
            MCP proxy run {scenario}, read from its audit chain and verified as it arrives.
          </p>
        ) : null}
      </header>
      <Separator />
      {controls}
      {problem === null ? null : (
        <div className="flex flex-wrap items-center gap-3">
          <Alert variant="destructive" className="w-auto">
            {problem.text}
          </Alert>
          {problem.offerCassette ? (
            <Button type="button" variant="outline" onClick={onUseCassette}>
              Use cassette instead
            </Button>
          ) : null}
        </div>
      )}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Contract">
          <ContractPanel contract={view.contract} />
        </Panel>
        <div className="space-y-4">
          <Panel title="Provenance graph">
            <ProvenanceGraph view={view} selectedId={selectedId} onSelect={setSelectedId} />
          </Panel>
          {following && view.endorsements.length > 0 ? (
            <Panel title="Awaiting the user">
              <p data-mcp-escalation>
                The proxy holds an escalated call until you answer. Confirm or Reject here (the
                server must be started with NOTARY_MCP_APPROVALS=1 and this page opened on the same
                machine), or run <code>notary-mcp-proxy approve|reject &lt;id&gt;</code>. The card
                closes when the proxy&apos;s audit chain shows the outcome.
              </p>
            </Panel>
          ) : null}
          {runId !== null && view.endorsements.length > 0 ? (
            <EndorsementPanel
              runId={runId}
              endorsements={view.endorsements}
              send={stream.send}
              events={stream.events}
              resolveFromEvents={mode !== "golden"}
              allowNearest={!following}
              toolByCallId={toolByCallId}
              onResolvedChange={onResolvedChange}
              onRejectedChange={onRejectedChange}
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
        <Card className="text-sm">
          <CardContent>
            <OraclePanel
              view={view}
              unresolvedEndorsements={unresolved}
              rejectedEndorsements={rejected.size}
            />
          </CardContent>
        </Card>
        <Panel title="What changed">
          <EffectsList view={view} />
        </Panel>
      </div>
      {viewMode === "three-lane" && !following ? (
        <Panel title="Three lanes">
          <ThreeLaneContainer
            apiUrl={apiUrl}
            scenario={scenario}
            mode={mode}
            webSocket={webSocket}
            notary={notary}
          />
        </Panel>
      ) : null}
      <AnchorFooter client={client} runId={runId} finished={view.finished !== null} />
    </>
  );
}

/** Mode `mcp` before a run is chosen: the controls and what to do next. */
function McpIdle({ controls }: { controls: ReactNode }) {
  return (
    <>
      <header className="space-y-1">
        <p className="text-xs font-medium tracking-widest text-muted-foreground uppercase">
          NOTARY
        </p>
        <h1 className="flex flex-wrap items-center gap-3 text-2xl font-semibold tracking-tight">
          Trust X-ray
          <Badge variant="muted" data-status="idle">
            idle
          </Badge>
          <Badge variant="outline">{laneLabel("notary", null)}</Badge>
        </h1>
      </header>
      <Separator />
      {controls}
      <p data-mcp-idle className="text-muted-foreground">
        {MCP_NO_RUN}
      </p>
    </>
  );
}

/** The Trust X-ray: the demo steps and controls on top, then the regions of one run. */
export function XRayView({
  apiUrl,
  scenario: initialScenario,
  mode: initialMode = DEFAULT_MODE,
  initialViewMode = "single",
  initialStep,
  webSocket,
}: XRayViewProps) {
  // Every choice goes through `settleSelection`, so a combination the server cannot serve (golden
  // for legitimate_bill or for the three-lane view) is never opened.
  const [initial] = useState(() =>
    settleSelection({ scenario: initialScenario, mode: initialMode, viewMode: initialViewMode }),
  );
  const [selection, setSelection] = useState(initial);
  // Steps 1 and 2 are the same screen; the address tells them apart.
  const [stepHint, setStepHint] = useState(initialStep);
  const [runKey, setRunKey] = useState(0);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  // An address that asked for such a combination is corrected in the address bar too.
  useEffect(() => {
    if (initial.note !== null) {
      window.history.replaceState(
        null,
        "",
        xrayUrl({ ...initial, ...(initialStep === undefined ? {} : { step: initialStep }) }),
      );
    }
  }, [initial, initialStep]);

  const apply = (next: Selection, hint?: number) => {
    const settled = settleSelection(next);
    setSelection(settled);
    setStepHint(hint);
    if (settled.scenario !== selection.scenario || settled.mode !== selection.mode) {
      setRunKey((key) => key + 1);
    }
    window.history.replaceState(
      null,
      "",
      xrayUrl({ ...settled, ...(hint === undefined ? {} : { step: hint }) }),
    );
  };

  const active = activeStep(selection.scenario, selection.mode, selection.viewMode, stepHint);
  const selectStep = (id: number) => {
    const step = DEMO_STEPS.find((item) => item.id === id);
    if (step === undefined) return;
    apply(
      { scenario: step.scenario, mode: step.mode, viewMode: step.viewMode },
      id === 2 ? 2 : undefined,
    );
  };

  const controls = (
    <RunControls
      apiUrl={apiUrl}
      scenario={selection.scenario}
      mode={selection.mode}
      viewMode={selection.viewMode}
      note={selection.note}
      steps={<DemoStepNav active={active} onSelect={selectStep} />}
      guide={<DemoGuide active={active} />}
      advancedOpen={advancedOpen}
      onAdvancedToggle={setAdvancedOpen}
      onScenarioChange={(next) => {
        apply({ ...selection, scenario: next });
      }}
      onModeChange={(next) => {
        apply(selectMode(selection, next));
      }}
      onViewModeChange={(next) => {
        apply({ ...selection, viewMode: next });
      }}
      onRunAgain={() => {
        setRunKey((key) => key + 1);
      }}
    />
  );

  return (
    <main className="mx-auto w-full max-w-[1600px] space-y-6 px-4 py-6 text-sm sm:px-6">
      {selection.mode === "mcp" && selection.scenario === "" ? (
        <McpIdle controls={controls} />
      ) : (
        <XRayRun
          key={runKey}
          apiUrl={apiUrl}
          scenario={selection.scenario}
          mode={selection.mode}
          viewMode={selection.viewMode}
          webSocket={webSocket}
          onUseCassette={() => {
            apply({ ...selection, mode: "cassette" });
          }}
          controls={controls}
        />
      )}
    </main>
  );
}
