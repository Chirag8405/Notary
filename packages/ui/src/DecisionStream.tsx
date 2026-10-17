import type { Event } from "@notary/schema";
import { useMemo } from "react";

import { decisionSummary, toDecisionRows } from "./decision-rows";
import type { ArgChip, DecisionRow } from "./decision-rows";
import { describeEvent } from "./describe-event";
import type { RunView } from "./run-view";

interface DecisionStreamCommon {
  selectedCallId?: string | null;
  onSelect?: (target: { callId: string; valueId?: string }) => void;
  /** Endorsements the viewer already answered; their "awaiting your confirmation" tag is hidden. */
  resolvedEndorsements?: ReadonlySet<string>;
}

/**
 * `view` draws one row per proposed call. `events` keeps the earlier plain list of events, one item
 * per event, for callers that have not moved to `view` yet.
 */
export type DecisionStreamProps =
  | (DecisionStreamCommon & { view: RunView })
  | (DecisionStreamCommon & { events: readonly Event[] });

const WAITING = "Waiting for events…";

const CHIP_CLASS: Record<ArgChip["originKind"], string> = {
  user: "border-green-500 bg-green-50 text-green-900",
  ledger: "border-blue-500 bg-blue-50 text-blue-900",
  tool: "border-amber-500 bg-amber-50 text-amber-900",
  email: "border-amber-500 bg-amber-50 text-amber-900",
  file: "border-amber-500 bg-amber-50 text-amber-900",
  web: "border-amber-500 bg-amber-50 text-amber-900",
  llm: "border-neutral-400 bg-neutral-50 text-neutral-800",
};

const VERDICT_CLASS = {
  ALLOW: "bg-green-100 text-green-900",
  ESCALATE: "bg-yellow-100 text-yellow-900",
  BLOCK: "bg-red-100 text-red-900",
} as const;

export function DecisionStream(props: DecisionStreamProps) {
  if ("view" in props) return <DecisionRows {...props} view={props.view} />;
  return <EventList events={props.events} />;
}

function EventList({ events }: { events: readonly Event[] }) {
  if (events.length === 0) {
    return <p className="text-sm text-neutral-500">{WAITING}</p>;
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

function chipLabel(chip: ArgChip): string {
  const origin = chip.originName === null ? chip.originKind : `tool:${chip.originName}`;
  return `${chip.param}: ${origin}`;
}

function rowState(row: DecisionRow, view: RunView): "decided" | "pending" | "ungated" {
  if (row.verdict !== null) return "decided";
  return view.lane === "notary" && view.finished === null ? "pending" : "ungated";
}

function DecisionRows({
  view,
  selectedCallId = null,
  onSelect,
  resolvedEndorsements,
}: DecisionStreamCommon & { view: RunView }) {
  const rows = useMemo(() => toDecisionRows(view), [view]);
  if (rows.length === 0) {
    return <p className="text-sm text-neutral-500">{WAITING}</p>;
  }
  return (
    <ol className="space-y-2 text-sm" aria-label="Decision stream">
      {rows.map((row) => {
        const state = rowState(row, view);
        const awaiting =
          row.endorsementId !== null &&
          row.verdict === "ESCALATE" &&
          resolvedEndorsements?.has(row.endorsementId) !== true;
        const anomaly = row.verdict === "BLOCK" && row.executed !== null;
        return (
          <li
            key={row.callId}
            data-event-type="call_proposed"
            data-call-id={row.callId}
            data-state={state}
            {...(row.verdict === null ? {} : { "data-verdict": row.verdict })}
            {...(anomaly ? { "data-anomaly": "executed after block" } : {})}
            aria-current={row.callId === selectedCallId ? "true" : undefined}
            onClick={() => onSelect?.({ callId: row.callId })}
            className={`space-y-1 rounded border p-2 ${row.callId === selectedCallId ? "ring-2 ring-indigo-500" : ""}`}
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-neutral-400">{String(row.seq).padStart(3, "0")}</span>
              <button
                type="button"
                data-row-select
                className="font-semibold underline-offset-2 hover:underline"
                onClick={(event) => {
                  event.stopPropagation();
                  onSelect?.({ callId: row.callId });
                }}
              >
                {row.tool}
              </button>
              <span className="font-mono text-xs text-neutral-500">
                {row.callId} <span data-manifest>{row.manifestShort}</span>
              </span>
              {row.verdict === null ? null : (
                <span
                  data-verdict-badge={row.verdict}
                  className={`rounded px-1 text-xs font-semibold ${VERDICT_CLASS[row.verdict]}`}
                >
                  {row.verdict}
                </span>
              )}
              {row.headlineReason === null ? null : (
                <span data-headline className="font-mono text-xs">
                  {row.headlineReason.code}
                </span>
              )}
            </div>
            <p data-summary className="font-mono">
              {row.verdict === null
                ? state === "pending"
                  ? "pending decision"
                  : "no policy check"
                : decisionSummary(row.callId, row.verdict)}
            </p>
            {row.args.length === 0 ? null : (
              <ul className="flex flex-wrap gap-2" aria-label="Arguments">
                {row.args.map((chip) => (
                  <li key={chip.param} className="flex items-center gap-1">
                    <button
                      type="button"
                      data-chip={chip.param}
                      data-origin={chip.originKind}
                      data-integrity={chip.integrity}
                      className={`rounded border px-1 text-xs ${CHIP_CLASS[chip.originKind]}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        onSelect?.({ callId: row.callId, valueId: chip.valueId });
                      }}
                    >
                      {chipLabel(chip)}
                      {chip.integrity === "untrusted" ? " untrusted" : ""}
                    </button>
                    <span data-preview className="font-mono text-xs">
                      {chip.preview}
                    </span>
                    <button
                      type="button"
                      data-hash-link
                      className="font-mono text-xs text-indigo-700 underline"
                      onClick={(event) => {
                        event.stopPropagation();
                        onSelect?.({ callId: row.callId, valueId: chip.valueId });
                      }}
                    >
                      {chip.hashShort}
                    </button>
                  </li>
                ))}
              </ul>
            )}
            {row.reasons.length === 0 ? null : (
              <ul className="space-y-0.5 text-xs" aria-label="Reasons">
                {row.reasons.map((reason, index) => (
                  <li
                    key={`${index}:${reason.check}`}
                    data-check={reason.check}
                    data-code={reason.code}
                    data-outcome={reason.outcome}
                  >
                    {reason.outcome === "fail" ? <strong>fail </strong> : null}
                    {reason.check} {reason.code} {reason.detail}
                  </li>
                ))}
              </ul>
            )}
            {row.executed === null ? null : (
              <p data-executed className="text-xs">
                Executed: {row.executed}
              </p>
            )}
            {anomaly ? (
              <p className="text-xs font-semibold text-red-700">executed after block</p>
            ) : null}
            {awaiting ? (
              <p data-awaiting className="text-xs font-semibold text-yellow-800">
                awaiting your confirmation
              </p>
            ) : null}
            {row.earlierDecisions.length === 0 ? null : (
              <details data-earlier-decisions className="text-xs">
                <summary>
                  earlier decisions:{" "}
                  {row.earlierDecisions
                    .map((d) =>
                      d.headlineReason === null
                        ? d.verdict
                        : `${d.verdict} (${d.headlineReason.code})`,
                    )
                    .join(", ")}
                </summary>
              </details>
            )}
          </li>
        );
      })}
    </ol>
  );
}
