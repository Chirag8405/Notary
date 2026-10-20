"use client";

import { CommandSchema } from "@notary/schema";
import type { Command, DiffRow, Event } from "@notary/schema";
import { cardOutcomes, highlightDiff } from "@notary/ui";
import type { CardOutcome, EndorsementView } from "@notary/ui";
import { useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { shownState } from "@/lib/card-state";
import type { Decision } from "@/lib/card-state";
import { originText } from "@/lib/guided";
import { describeSendError } from "@/lib/send-error";
import { paramText, toolText } from "@/lib/plain-language";

export interface ApprovalDialogProps {
  runId: string;
  endorsements: readonly EndorsementView[];
  events: readonly Event[];
  send: (command: Command) => void;
  toolByCallId: Readonly<Record<string, string>>;
  /** False once the run's connection has closed: nothing can be sent, so the answers are off. */
  connected?: boolean;
  /** Starts the run again; offered when the connection is lost. */
  onRunAgain?: () => void;
}

const OPEN: CardOutcome = { kind: "open" };

function Marked({ text, positions }: { text: string; positions: readonly number[] }) {
  return (
    <code className="font-mono break-all">
      {highlightDiff(text, positions).map((segment, index) =>
        segment.differs ? (
          <mark key={index} className="rounded-sm bg-bad/25 px-px font-bold text-bad-strong">
            {segment.text}
          </mark>
        ) : (
          <span key={index}>{segment.text}</span>
        ),
      )}
    </code>
  );
}

function Row({ row }: { row: DiffRow }) {
  const known = row.nearest_ledger_value;
  const comparable = known !== null && Array.from(known).length === Array.from(row.preview).length;
  return (
    <div className="space-y-2 rounded-lg border p-3">
      <p className="text-sm font-medium">{paramText(row.param)}</p>
      <div className="space-y-1 text-sm">
        <p className="text-muted-foreground">The agent wants to use</p>
        <Marked text={row.preview} positions={row.differing_positions} />
        <p className="text-xs text-muted-foreground">{originText(row.origin)}</p>
      </div>
      {known === null ? (
        <p className="text-sm text-muted-foreground">You have nothing similar saved.</p>
      ) : (
        <div className="space-y-1 text-sm">
          <p className="text-muted-foreground">You normally use</p>
          {comparable ? (
            <Marked text={known} positions={row.differing_positions} />
          ) : (
            <code className="font-mono break-all">{known}</code>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * The approval moment in plain words. It opens by itself when NOTARY pauses an action, shows what
 * the agent wants next to what you normally use, and cannot be closed without an answer. Like the
 * Trust X-ray card it only sends the command; the run's own events say how the card ended.
 */
export function ApprovalDialog({
  runId,
  endorsements,
  events,
  send,
  toolByCallId,
  connected = true,
  onRunAgain,
}: ApprovalDialogProps) {
  const [clicks, setClicks] = useState<ReadonlyMap<string, Decision>>(() => new Map());
  const [error, setError] = useState<string | null>(null);
  const clicked = useRef(new Set<string>());

  const outcomes = cardOutcomes(events);
  const open = endorsements.find((view) => {
    const id = view.endorsement.endorsement_id;
    const outcome = outcomes.byEndorsementId.get(id) ?? OPEN;
    const state = shownState(outcome, clicks.get(id) ?? null, false);
    return state === "pending" || state === "sending";
  });
  if (open === undefined) return null;

  const id = open.endorsement.endorsement_id;
  const sending = clicks.has(id) || !connected;
  const rows = open.endorsement.card.rows;
  const remaining = outcomes.remainingBefore.get(id) ?? null;
  const exhausted = remaining === 0;
  const canUseKnown = rows.length > 0 && rows.every((row) => row.nearest_ledger_value !== null);
  const tool = toolByCallId[open.endorsement.call_id];

  const decide = (decision: Decision) => {
    if (clicked.current.has(id)) return;
    clicked.current.add(id);
    try {
      send(
        CommandSchema.parse({
          type: "endorsement_decision",
          run_id: runId,
          endorsement_id: id,
          decision,
        }),
      );
    } catch (failure) {
      clicked.current.delete(id);
      setError(describeSendError(failure));
      return;
    }
    setError(null);
    setClicks((current) => new Map(current).set(id, decision));
  };

  return (
    <Dialog open>
      <DialogContent
        showCloseButton={false}
        data-approval={id}
        onEscapeKeyDown={(event) => {
          event.preventDefault();
        }}
        onInteractOutside={(event) => {
          event.preventDefault();
        }}
        className="sm:max-w-lg"
      >
        <DialogHeader>
          <DialogTitle>Is this account right?</DialogTitle>
          <DialogDescription>
            The agent wants to {(tool === undefined ? "do this" : toolText(tool)).toLowerCase()},
            but the details are new to you. Check them before anything happens.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          {rows.map((row) => (
            <Row key={`${row.param}:${row.value_id}`} row={row} />
          ))}
          {remaining === null ? null : (
            <p className="text-xs text-muted-foreground">
              Approvals left for this task: {remaining}
            </p>
          )}
          {connected ? null : (
            <div
              role="alert"
              className="space-y-2 rounded-lg border border-bad bg-bad-soft p-3 text-sm text-bad-strong"
            >
              <p>
                The connection to the server closed, so this question can no longer be answered. The
                server may have restarted.
              </p>
              {onRunAgain === undefined ? null : (
                <Button type="button" variant="outline" onClick={onRunAgain}>
                  Run again
                </Button>
              )}
            </div>
          )}
          {exhausted ? (
            <p role="alert" className="text-sm text-destructive">
              You have no approvals left, so this action stays stopped.
            </p>
          ) : null}
          {error === null ? null : (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
        </div>
        <DialogFooter className="gap-2 sm:flex-col sm:items-stretch">
          {canUseKnown ? (
            <Button
              type="button"
              disabled={sending}
              onClick={() => {
                decide("use_nearest");
              }}
            >
              Use the account I normally use
            </Button>
          ) : null}
          <Button
            type="button"
            variant={canUseKnown ? "outline" : "default"}
            disabled={sending}
            onClick={() => {
              decide("reject");
            }}
          >
            No, stop this
          </Button>
          <Button
            type="button"
            variant="destructive"
            disabled={sending || exhausted}
            onClick={() => {
              decide("approve");
            }}
          >
            Approve anyway (I trust this)
          </Button>
          <p className="text-xs text-muted-foreground">
            Approving sends the money to the account the agent found. NOTARY cannot stop a choice
            you make yourself.
          </p>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
