import type { DiffRow, Endorsement } from "@notary/schema";
import { useEffect, useRef } from "react";

import { highlightDiff } from "./diff-highlight";
import type { Segment } from "./diff-highlight";

export type CardState =
  | "pending"
  | "sending"
  | "approved"
  | "rejected"
  | "timed_out"
  | "cancelled"
  | "replaced"
  | "blocked"
  | "conflict";

export interface EndorsementCardProps {
  endorsement: Endorsement;
  /** The approvals left in the run's budget; null while unknown. */
  remainingApprovals: number | null;
  state: CardState;
  onDecide: (decision: "approve" | "reject" | "use_nearest") => void;
  /** The tool the call wants to run, for the title; the call id is used when it is missing. */
  toolName?: string;
  /** A message to show when the last attempt failed. */
  error?: string | null;
  /**
   * Whether "use the nearest known value" may be offered (default true). False for a run that has
   * no such path, such as one of the MCP proxy: the button is not shown at all.
   */
  allowNearest?: boolean;
}

const BUTTON =
  "inline-flex h-9 items-center justify-center rounded-md px-4 text-sm font-medium transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50";
/** Reject keeps the call blocked: the primary action. Confirm approves the value shown: outlined. */
const REJECT_BUTTON = `${BUTTON} bg-primary text-primary-foreground hover:bg-primary/90`;
const CONFIRM_BUTTON = `${BUTTON} border border-amber-500 bg-background text-amber-900 hover:bg-amber-50`;

/** The third choice: it approves nothing, so it looks like a plain secondary action. */
const NEAREST_BUTTON = `${BUTTON} border border-input bg-background text-foreground hover:bg-muted`;

const STATE_TEXT: Partial<Record<CardState, string>> = {
  sending: "Sending...",
  approved: "You confirmed this request",
  rejected: "This request was rejected",
  timed_out: "No answer in time: the request was rejected",
  cancelled: "The request was cancelled",
  replaced: "You asked for the nearest known value instead",
  blocked: "You confirmed this request, but the monitor blocked the call",
  conflict: "This request is no longer open",
};

function Highlighted({ segments, marker }: { segments: readonly Segment[]; marker: string }) {
  return (
    <>
      {segments.map((segment, index) =>
        segment.differs ? (
          <mark
            key={`${marker}:${index}`}
            data-differs
            className="bg-red-200 font-bold underline decoration-red-700"
          >
            {segment.text}
          </mark>
        ) : (
          <span key={`${marker}:${index}`}>{segment.text}</span>
        ),
      )}
    </>
  );
}

function originText(row: DiffRow): string {
  return row.origin.kind === "tool" ? `tool:${row.origin.name}` : row.origin.kind;
}

/** The ledger value is highlighted with the same positions only when it is as long as the proposal. */
function LedgerValue({ row }: { row: DiffRow }) {
  if (row.nearest_ledger_value === null) {
    return <p data-ledger-empty>no similar ledger entry</p>;
  }
  const comparable = Array.from(row.nearest_ledger_value).length === Array.from(row.preview).length;
  return (
    <p>
      nearest ledger value:{" "}
      <code data-ledger className="font-mono">
        {comparable ? (
          <Highlighted
            segments={highlightDiff(row.nearest_ledger_value, row.differing_positions)}
            marker="ledger"
          />
        ) : (
          row.nearest_ledger_value
        )}
      </code>
      {comparable ? null : (
        <span data-length-note className="ml-2 text-xs text-muted-foreground">
          different length: positions not comparable
        </span>
      )}
    </p>
  );
}

/**
 * The human-in-the-loop moment: what the agent wants to do with a value that is not in the
 * ledger, and its buttons: confirm it, reject it, or use the nearest known value instead. It only
 * calls `onDecide`; it builds no command and never focuses a
 * button, so nothing can be confirmed by accident.
 */
export function EndorsementCard({
  endorsement,
  remainingApprovals,
  state,
  onDecide,
  toolName,
  error,
  allowNearest = true,
}: EndorsementCardProps) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
  }, []);

  const exhausted = remainingApprovals === 0;
  const disabled = state !== "pending" || exhausted;
  const stateText = STATE_TEXT[state];
  // Offered only when the ledger has a value to propose for every parameter on the card.
  const canUseNearest =
    allowNearest &&
    endorsement.card.rows.length > 0 &&
    endorsement.card.rows.every((row) => row.nearest_ledger_value !== null);

  return (
    <section
      role="group"
      aria-label="Endorsement request"
      data-endorsement-id={endorsement.endorsement_id}
      data-state={state}
      className="space-y-3 rounded border-2 border-yellow-500 bg-yellow-50 p-3 text-sm"
    >
      <h3 ref={heading} tabIndex={-1} className="font-semibold">
        Confirm {toolName ?? endorsement.call_id}?
      </h3>
      {endorsement.card.rows.map((row) => (
        <div
          key={`${row.param}:${row.value_id}`}
          data-row
          data-param={row.param}
          className="space-y-1"
        >
          <p className="font-semibold">{row.param}</p>
          <p>
            <code data-proposed className="font-mono">
              <Highlighted
                segments={highlightDiff(row.preview, row.differing_positions)}
                marker="proposed"
              />
            </code>
          </p>
          <p className="text-xs">
            <span data-origin={row.origin.kind}>{originText(row)}</span>
            {", "}
            <span data-integrity={row.integrity}>{row.integrity}</span>
          </p>
          <LedgerValue row={row} />
          <p>This value is not in your ledger.</p>
        </div>
      ))}
      {remainingApprovals === null ? null : (
        <p data-approvals>Approvals left: {remainingApprovals}</p>
      )}
      {exhausted ? <p data-exhausted>No approvals left: the call is blocked</p> : null}
      {stateText === undefined ? null : <p data-state-text>{stateText}</p>}
      {error === undefined || error === null || error === "" ? null : (
        <p role="alert" className="text-red-700">
          {error}
        </p>
      )}
      {state === "conflict" ? null : (
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={disabled}
            className={CONFIRM_BUTTON}
            onClick={() => {
              onDecide("approve");
            }}
          >
            Confirm
          </button>
          <button
            type="button"
            disabled={disabled}
            className={REJECT_BUTTON}
            onClick={() => {
              onDecide("reject");
            }}
          >
            Reject
          </button>
          {canUseNearest ? (
            <button
              type="button"
              disabled={state !== "pending"}
              className={NEAREST_BUTTON}
              onClick={() => {
                onDecide("use_nearest");
              }}
            >
              Use nearest known value
            </button>
          ) : null}
        </div>
      )}
    </section>
  );
}
