"use client";

import { describeClose } from "@notary/client";
import { CommandSchema } from "@notary/schema";
import type { Command, Event } from "@notary/schema";
import { EndorsementCard, cardOutcomes } from "@notary/ui";
import type { CardOutcome, CardState, EndorsementView } from "@notary/ui";
import { useEffect, useMemo, useRef, useState } from "react";

import { shownState } from "@/lib/card-state";
import type { Decision } from "@/lib/card-state";

export interface EndorsementPanelProps {
  runId: string;
  endorsements: readonly EndorsementView[];
  /** Every event of the run so far. The stream decides when a card is resolved. */
  events: readonly Event[];
  /** Answers on the run socket; throws when the socket is closed. */
  send: (command: Command) => void;
  closeCode?: number;
  /**
   * Whether the events answer the cards. False for the golden replay, whose events after a card
   * are canned text, not an answer: its cards stay as they are (a click ends in 4409).
   */
  resolveFromEvents?: boolean;
  /** Call id to tool name, for the card title. */
  toolByCallId?: Readonly<Record<string, string>>;
  /** Called, never during render, when the set of answered cards changes. */
  onResolvedChange?: (resolved: ReadonlySet<string>) => void;
  /** Called, never during render, when the set of cards the user rejected changes. */
  onRejectedChange?: (rejected: ReadonlySet<string>) => void;
  /** False for an MCP proxy run, which has no "nearest known value" path (default true). */
  allowNearest?: boolean;
}

interface Click {
  decision: Decision;
}

const OPEN: CardOutcome = { kind: "open" };
const RESOLVED: ReadonlySet<CardState> = new Set<CardState>([
  "approved",
  "rejected",
  "timed_out",
  "cancelled",
  "replaced",
  "blocked",
]);

function sortedKey(ids: readonly string[]): string {
  return [...ids].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).join("\n");
}

/**
 * The cards of the run's endorsements and the answers the user gives.
 *
 * The panel makes no request. A click sends the command and the card reads "sending"; the run's
 * own events then say how it ended (`cardOutcomes`): approved, replaced by the nearest known
 * value, blocked after the answer, or closed. "Approvals left" comes from the contract in the
 * stream. A closed socket never resolves a card; only one closed with 4409 turns an open card
 * into "no longer open".
 */
export function EndorsementPanel({
  runId,
  endorsements,
  events,
  send,
  closeCode,
  resolveFromEvents = true,
  toolByCallId,
  onResolvedChange,
  onRejectedChange,
  allowNearest = true,
}: EndorsementPanelProps) {
  const [clicks, setClicks] = useState<ReadonlyMap<string, Click>>(() => new Map());
  const [errors, setErrors] = useState<ReadonlyMap<string, string>>(() => new Map());
  // Mirrors `clicks` so two clicks in the same tick still send one command.
  const clicked = useRef(new Set<string>());
  const sendRef = useRef(send);
  useEffect(() => {
    sendRef.current = send;
  });

  const outcomes = useMemo(() => cardOutcomes(events), [events]);
  const conflict = closeCode !== undefined && describeClose(closeCode) === "run_conflict";

  const shown = endorsements.map((view) => {
    const id = view.endorsement.endorsement_id;
    const outcome = resolveFromEvents ? (outcomes.byEndorsementId.get(id) ?? OPEN) : OPEN;
    const state = shownState(outcome, clicks.get(id)?.decision ?? null, conflict);
    return { view, id, outcome, state };
  });

  const resolvedKey = sortedKey(shown.filter((card) => RESOLVED.has(card.state)).map((c) => c.id));
  const rejectedKey = sortedKey(shown.filter((card) => card.state === "rejected").map((c) => c.id));
  const onResolvedRef = useRef(onResolvedChange);
  const onRejectedRef = useRef(onRejectedChange);
  useEffect(() => {
    onResolvedRef.current = onResolvedChange;
    onRejectedRef.current = onRejectedChange;
  });
  const lastResolved = useRef("");
  useEffect(() => {
    if (resolvedKey === lastResolved.current) return;
    lastResolved.current = resolvedKey;
    onResolvedRef.current?.(new Set(resolvedKey === "" ? [] : resolvedKey.split("\n")));
  }, [resolvedKey]);
  const lastRejected = useRef("");
  useEffect(() => {
    if (rejectedKey === lastRejected.current) return;
    lastRejected.current = rejectedKey;
    onRejectedRef.current?.(new Set(rejectedKey === "" ? [] : rejectedKey.split("\n")));
  }, [rejectedKey]);

  const decide = (endorsementId: string, decision: Decision) => {
    const card = shown.find((item) => item.id === endorsementId);
    if (card?.state !== "pending") return;
    if (clicked.current.has(endorsementId)) return;
    clicked.current.add(endorsementId);
    try {
      const command = CommandSchema.parse({
        type: "endorsement_decision",
        run_id: runId,
        endorsement_id: endorsementId,
        decision,
      });
      sendRef.current(command);
    } catch (error) {
      clicked.current.delete(endorsementId);
      const message = error instanceof Error ? error.message : "could not send the decision";
      setErrors((current) => new Map(current).set(endorsementId, message));
      return;
    }
    setErrors((current) => {
      const next = new Map(current);
      next.delete(endorsementId);
      return next;
    });
    setClicks((current) => new Map(current).set(endorsementId, { decision }));
  };

  return (
    <section aria-label="Endorsements" className="space-y-3">
      {shown.map(({ view, id, outcome, state }) => {
        const tool = toolByCallId?.[view.endorsement.call_id];
        return (
          <EndorsementCard
            key={id}
            endorsement={view.endorsement}
            remainingApprovals={
              outcome.kind === "open" ? (outcomes.remainingBefore.get(id) ?? null) : null
            }
            state={state}
            error={errors.get(id) ?? null}
            allowNearest={allowNearest}
            onDecide={(decision) => {
              decide(id, decision);
            }}
            {...(tool === undefined ? {} : { toolName: tool })}
          />
        );
      })}
    </section>
  );
}
