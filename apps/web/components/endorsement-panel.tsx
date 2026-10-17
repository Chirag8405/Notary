"use client";

import { describeClose } from "@notary/client";
import type { PendingList } from "@notary/client";
import { CommandSchema } from "@notary/schema";
import type { Endorsement } from "@notary/schema";
import type { Command } from "@notary/schema";
import { EndorsementCard } from "@notary/ui";
import type { CardState, EndorsementView } from "@notary/ui";
import { useCallback, useEffect, useRef, useState } from "react";

/** What the panel needs from one entry of the server's pending list. */
export type PendingItem = Pick<PendingList["pending"][number], "remaining_approvals"> & {
  endorsement: Pick<Endorsement, "endorsement_id">;
};

export interface EndorsementPanelProps {
  runId: string;
  endorsements: readonly EndorsementView[];
  /** Answers on the run socket; throws when the socket is closed. */
  send: (command: Command) => void;
  /** The endorsements that still wait for the user, with the approvals left. */
  fetchPending: () => Promise<readonly PendingItem[]>;
  closeCode?: number;
  /** Changes when new stream events arrive: the pending list is read again. */
  eventCount?: number;
  /** Call id to tool name, for the card title. */
  toolByCallId?: Readonly<Record<string, string>>;
  /** Called, never during render, when the set of answered cards changes. */
  onResolvedChange?: (resolved: ReadonlySet<string>) => void;
}

type Decision = "approve" | "reject";

interface CardInfo {
  state: CardState;
  decision: Decision | null;
  error: string | null;
}

const RESOLVED: Record<Decision, CardState> = { approve: "approved", reject: "rejected" };

/**
 * The cards of the run's pending endorsements and the answers the user gives.
 *
 * A card moves to "sending" when its command was sent, and to approved or rejected once a
 * SUCCESSFUL pending list no longer contains it; a failed read never resolves anything. A socket
 * closed with 4409 turns every open card into "conflict". The decision shown is the user's click:
 * the stream's own events carry the outcome the server confirmed.
 */
export function EndorsementPanel({
  runId,
  endorsements,
  send,
  fetchPending,
  closeCode,
  eventCount,
  toolByCallId,
  onResolvedChange,
}: EndorsementPanelProps) {
  const [cards, setCards] = useState<ReadonlyMap<string, CardInfo>>(() => new Map());
  const [remaining, setRemaining] = useState<ReadonlyMap<string, number>>(() => new Map());

  // The map is mirrored in a ref so that every update starts from the latest value, even when two
  // events arrive before React has rendered.
  const cardsRef = useRef<ReadonlyMap<string, CardInfo>>(cards);
  const inFlight = useRef(new Set<string>());
  const requests = useRef(0);
  const alive = useRef(true);
  const sendRef = useRef(send);
  const fetchRef = useRef(fetchPending);

  useEffect(() => {
    sendRef.current = send;
    fetchRef.current = fetchPending;
  });
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const write = useCallback((next: ReadonlyMap<string, CardInfo>) => {
    cardsRef.current = next;
    setCards(next);
  }, []);

  const onResolvedRef = useRef(onResolvedChange);
  useEffect(() => {
    onResolvedRef.current = onResolvedChange;
  });
  const lastResolved = useRef("");
  useEffect(() => {
    const ids = [...cards]
      .filter(([, info]) => info.state === "approved" || info.state === "rejected")
      .map(([id]) => id)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const key = ids.join("\n");
    if (key === lastResolved.current) return;
    lastResolved.current = key;
    onResolvedRef.current?.(new Set(ids));
  }, [cards]);

  const poll = useCallback(() => {
    requests.current += 1;
    const mine = requests.current;
    const accept = (list: readonly PendingItem[]) => {
      if (!alive.current || mine !== requests.current) return;
      const listed = new Map(list.map((item) => [item.endorsement.endorsement_id, item]));
      setRemaining(new Map([...listed].map(([id, item]) => [id, item.remaining_approvals])));
      const next = new Map(cardsRef.current);
      let changed = false;
      for (const [id, info] of cardsRef.current) {
        if (info.state === "sending" && info.decision !== null && !listed.has(id)) {
          next.set(id, { state: RESOLVED[info.decision], decision: info.decision, error: null });
          inFlight.current.delete(id);
          changed = true;
        }
      }
      if (changed) write(next);
    };
    // A failed read changes nothing; the next trigger tries again.
    const ignore = () => undefined;
    try {
      fetchRef.current().then(accept, ignore);
    } catch {
      ignore();
    }
  }, [write]);

  useEffect(() => {
    poll();
  }, [poll, endorsements, eventCount]);

  useEffect(() => {
    if (closeCode === undefined || describeClose(closeCode) !== "run_conflict") return;
    const next = new Map(cardsRef.current);
    let changed = false;
    for (const view of endorsements) {
      const id = view.endorsement.endorsement_id;
      const info = cardsRef.current.get(id);
      const state = info?.state ?? "pending";
      if (state === "pending" || state === "sending") {
        next.set(id, { state: "conflict", decision: info?.decision ?? null, error: null });
        inFlight.current.delete(id);
        changed = true;
      }
    }
    if (changed) write(next);
  }, [closeCode, endorsements, write]);

  const decide = (endorsementId: string, decision: Decision) => {
    if (inFlight.current.has(endorsementId)) return;
    if ((cardsRef.current.get(endorsementId)?.state ?? "pending") !== "pending") return;
    inFlight.current.add(endorsementId);
    try {
      const command = CommandSchema.parse({
        type: "endorsement_decision",
        run_id: runId,
        endorsement_id: endorsementId,
        decision,
      });
      sendRef.current(command);
    } catch (error) {
      inFlight.current.delete(endorsementId);
      const message = error instanceof Error ? error.message : "could not send the decision";
      write(
        new Map(cardsRef.current).set(endorsementId, {
          state: "pending",
          decision: null,
          error: message,
        }),
      );
      return;
    }
    write(
      new Map(cardsRef.current).set(endorsementId, { state: "sending", decision, error: null }),
    );
    poll();
  };

  return (
    <section aria-label="Endorsements" className="space-y-3">
      {endorsements.map((view) => {
        const id = view.endorsement.endorsement_id;
        const info = cards.get(id);
        const tool = toolByCallId?.[view.endorsement.call_id];
        return (
          <EndorsementCard
            key={id}
            endorsement={view.endorsement}
            remainingApprovals={remaining.get(id) ?? null}
            state={info?.state ?? "pending"}
            error={info?.error ?? null}
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
