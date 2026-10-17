import { CommandSchema } from "@notary/schema";
import type { Command, Event } from "@notary/schema";
import { foldEvents } from "@notary/ui";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EndorsementPanel } from "@/components/endorsement-panel";

import { CARD, REPLACED, TO_REQUEST } from "./card-events";

const RUN_ID = foldEvents(TO_REQUEST).runId ?? "";

afterEach(cleanup);

function mount() {
  const send = vi.fn<(command: Command) => void>();
  const onResolved = vi.fn<(resolved: ReadonlySet<string>) => void>();
  const onRejected = vi.fn<(rejected: ReadonlySet<string>) => void>();
  const props = (events: readonly Event[]) => ({
    runId: RUN_ID,
    events,
    endorsements: foldEvents(events).endorsements,
    send,
    onResolvedChange: onResolved,
    onRejectedChange: onRejected,
  });
  const { rerender } = render(<EndorsementPanel {...props(TO_REQUEST)} />);
  return {
    send,
    onResolved,
    onRejected,
    /** The stream moved on. */
    stream: (events: readonly Event[]) => {
      rerender(<EndorsementPanel {...props(events)} />);
    },
  };
}

const nearest = (): HTMLButtonElement =>
  screen.getByRole<HTMLButtonElement>("button", { name: "Use nearest known value" });

describe("EndorsementPanel: use the nearest known value", () => {
  it("sends exactly one valid use_nearest command [I4]", () => {
    const d = mount();
    fireEvent.click(nearest());
    fireEvent.click(nearest());
    expect(d.send).toHaveBeenCalledTimes(1);
    const command: unknown = d.send.mock.calls[0]?.[0];
    expect(CommandSchema.safeParse(command).success).toBe(true);
    expect(command).toEqual({
      type: "endorsement_decision",
      run_id: RUN_ID,
      endorsement_id: CARD,
      decision: "use_nearest",
    });
  });

  it("resolves to replaced once the stream proposes the nearest call, and is not a rejection [I4]", () => {
    const d = mount();
    fireEvent.click(nearest());
    d.stream(REPLACED);
    expect(
      document.querySelector(`[data-endorsement-id="${CARD}"]`)?.getAttribute("data-state"),
    ).toBe("replaced");
    expect(screen.getByText("You asked for the nearest known value instead")).toBeTruthy();
    expect([...(d.onResolved.mock.calls.at(-1)?.[0] ?? [])]).toEqual([CARD]);
    expect(d.onRejected).not.toHaveBeenCalled();
  });
});
