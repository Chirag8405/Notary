import type { DiffRow, Endorsement } from "@notary/schema";
import { useEffect, useRef, useState } from "react";

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
  onDecide: (decision: "approve" | "reject" | "use_nearest", code?: string) => void;
  /** The tool the call wants to run, for the title; the call id is used when it is missing. */
  toolName?: string;
  /** A message to show when the last attempt failed. */
  error?: string | null;
  /**
   * Whether "use the nearest known value" may be offered (default true). False for a run that has
   * no such path, such as one of the MCP proxy: the button is not shown at all.
   */
  allowNearest?: boolean;
  /**
   * Whether Confirm needs the one-time code the MCP proxy printed in its own terminal (default
   * false). The field is shown and Confirm stays off until something is typed; the code goes to
   * `onDecide` with the approval and is not kept.
   */
  askCode?: boolean;
}

const BUTTON =
  "inline-flex h-9 items-center justify-center rounded-md px-4 text-sm font-medium transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50";
/** Reject keeps the call blocked: the primary action. Confirm approves the value shown: outlined. */
const REJECT_BUTTON = `${BUTTON} bg-primary text-primary-foreground hover:bg-primary/90`;
const CONFIRM_BUTTON = `${BUTTON} border border-warn bg-background text-warn-strong hover:bg-warn-soft`;

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
            className="rounded-sm bg-bad/25 px-px font-bold text-bad-strong underline decoration-bad"
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

const LABEL = "text-xs font-medium tracking-wide text-muted-foreground uppercase";

/** The ledger value is highlighted with the same positions only when it is as long as the proposal. */
function LedgerValue({ row }: { row: DiffRow }) {
  if (row.nearest_ledger_value === null) {
    return (
      <div className="space-y-1">
        <p className={LABEL}>Nearest known value</p>
        <p data-ledger-empty className="text-muted-foreground">
          no similar ledger entry
        </p>
      </div>
    );
  }
  const comparable = Array.from(row.nearest_ledger_value).length === Array.from(row.preview).length;
  return (
    <div className="space-y-1">
      <p className={LABEL}>Nearest known value</p>
      <p>
        <span className="sr-only">nearest ledger value: </span>
        <code data-ledger className="font-mono break-all">
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
          <span data-length-note className="ml-2 block text-xs text-muted-foreground">
            different length: positions not comparable
          </span>
        )}
      </p>
    </div>
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
  askCode = false,
}: EndorsementCardProps) {
  const heading = useRef<HTMLHeadingElement>(null);
  const [code, setCode] = useState("");
  useEffect(() => {
    heading.current?.focus();
  }, []);

  const exhausted = remainingApprovals === 0;
  const disabled = state !== "pending" || exhausted;
  const codeMissing = askCode && code.trim() === "";
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
      className="space-y-4 rounded-lg border-2 border-warn bg-warn-soft p-4 text-sm text-foreground"
    >
      <header className="space-y-1">
        <p className="text-xs font-semibold tracking-wide text-warn-strong uppercase">
          Needs your decision
        </p>
        <h3 ref={heading} tabIndex={-1} className="text-lg font-semibold outline-none">
          Confirm {toolName ?? endorsement.call_id}?
        </h3>
        <p className="text-muted-foreground">
          The agent wants to use a value you have not used before. Compare it with what you know,
          then choose.
        </p>
      </header>
      {endorsement.card.rows.map((row) => (
        <div
          key={`${row.param}:${row.value_id}`}
          data-row
          data-param={row.param}
          className="space-y-3 rounded-md border bg-card p-3"
        >
          <p className="font-semibold">{row.param}</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <p className={LABEL}>Agent proposes</p>
              <p>
                <code data-proposed className="font-mono break-all">
                  <Highlighted
                    segments={highlightDiff(row.preview, row.differing_positions)}
                    marker="proposed"
                  />
                </code>
              </p>
              <p className="text-xs text-muted-foreground">
                <span data-origin={row.origin.kind}>{originText(row)}</span>
                {", "}
                <span data-integrity={row.integrity}>{row.integrity}</span>
              </p>
            </div>
            <LedgerValue row={row} />
          </div>
          <p className="font-medium text-warn-strong">This value is not in your ledger.</p>
        </div>
      ))}
      {remainingApprovals === null ? null : (
        <p data-approvals className="text-xs text-muted-foreground">
          Approvals left: {remainingApprovals}
        </p>
      )}
      {exhausted ? (
        <p data-exhausted className="font-medium text-bad-strong">
          No approvals left: the call is blocked
        </p>
      ) : null}
      {stateText === undefined ? null : (
        <p data-state-text className="font-medium">
          {stateText}
        </p>
      )}
      {error === undefined || error === null || error === "" ? null : (
        <p role="alert" className="text-bad-strong">
          {error}
        </p>
      )}
      {askCode && state !== "conflict" ? (
        <label className="block space-y-1">
          <span className={LABEL}>Approval code (shown in the proxy&apos;s terminal)</span>
          <input
            type="text"
            data-approval-code
            autoComplete="off"
            spellCheck={false}
            maxLength={64}
            value={code}
            disabled={disabled}
            onChange={(event) => {
              setCode(event.target.value);
            }}
            className="block h-9 w-full rounded-md border border-input bg-background px-3 font-mono text-sm"
          />
        </label>
      ) : null}
      {state === "conflict" ? null : (
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={disabled || codeMissing}
            className={CONFIRM_BUTTON}
            onClick={() => {
              if (askCode) onDecide("approve", code.trim());
              else onDecide("approve");
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
