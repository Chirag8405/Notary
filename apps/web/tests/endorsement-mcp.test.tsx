import { CommandSchema } from "@notary/schema";
import type { Command, Event } from "@notary/schema";
import { foldEvents } from "@notary/ui";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EndorsementPanel } from "@/components/endorsement-panel";

import { APPROVED, CARD, REJECTED, TO_REQUEST } from "./card-events";

const RUN_ID = foldEvents(TO_REQUEST).runId ?? "";

afterEach(cleanup);

/** The panel the way an MCP proxy run mounts it: no "nearest known value" path. */
function mount(allowNearest: boolean) {
  const send = vi.fn<(command: Command) => void>();
  const props = (events: readonly Event[]) => ({
    runId: RUN_ID,
    events,
    endorsements: foldEvents(events).endorsements,
    send,
    allowNearest,
  });
  const { rerender } = render(<EndorsementPanel {...props(TO_REQUEST)} />);
  return {
    send,
    stream: (events: readonly Event[]) => {
      rerender(<EndorsementPanel {...props(events)} />);
    },
  };
}

const state = (): string | null | undefined =>
  document.querySelector(`[data-endorsement-id="${CARD}"]`)?.getAttribute("data-state");

describe("EndorsementPanel on an MCP proxy run", () => {
  it("hides use_nearest for an MCP run and shows it otherwise [I4]", () => {
    mount(false);
    expect(screen.queryByRole("button", { name: "Use nearest known value" })).toBeNull();
    expect(screen.getByRole("button", { name: "Confirm" })).toBeTruthy();
    cleanup();
    mount(true);
    expect(screen.getByRole("button", { name: "Use nearest known value" })).toBeTruthy();
  });

  it("Confirm sends one valid approve command and the card only says sending [I4]", () => {
    const d = mount(false);
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(d.send).toHaveBeenCalledTimes(1);
    const command: unknown = d.send.mock.calls[0]?.[0];
    expect(CommandSchema.safeParse(command).success).toBe(true);
    expect(command).toEqual({
      type: "endorsement_decision",
      run_id: RUN_ID,
      endorsement_id: CARD,
      decision: "approve",
    });
    // sending the command does not close the card: only the stream does
    expect(state()).toBe("sending");
  });

  it("closes as approved only when the chain shows the second decision [I4]", () => {
    const d = mount(false);
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    d.stream(APPROVED);
    expect(state()).toBe("approved");
  });

  it("Reject sends a reject command and closes as rejected only from the stream [I4]", () => {
    const d = mount(false);
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    expect(d.send.mock.calls[0]?.[0]).toEqual({
      type: "endorsement_decision",
      run_id: RUN_ID,
      endorsement_id: CARD,
      decision: "reject",
    });
    expect(state()).toBe("sending");
    d.stream(REJECTED);
    expect(state()).toBe("rejected");
  });
});
