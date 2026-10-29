import { CommandSchema } from "@notary/schema";
import type { Command } from "@notary/schema";
import { foldEvents } from "@notary/ui";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EndorsementPanel } from "@/components/endorsement-panel";

import { CARD, TO_REQUEST } from "./card-events";

const RUN_ID = foldEvents(TO_REQUEST).runId ?? "";

afterEach(cleanup);

/** The panel the way an MCP proxy run mounts it: no nearest value, and a code to type. */
function mount(askCode: boolean) {
  const send = vi.fn<(command: Command) => void>();
  render(
    <EndorsementPanel
      runId={RUN_ID}
      events={TO_REQUEST}
      endorsements={foldEvents(TO_REQUEST).endorsements}
      send={send}
      allowNearest={false}
      askCode={askCode}
    />,
  );
  return send;
}

const field = (): HTMLInputElement => {
  const input = document.querySelector<HTMLInputElement>("[data-approval-code]");
  if (input === null) throw new Error("no approval code field");
  return input;
};

describe("EndorsementPanel asking for the proxy's approval code", () => {
  it("shows no field when the run does not ask for a code", () => {
    mount(false);
    expect(document.querySelector("[data-approval-code]")).toBeNull();
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Confirm" }).disabled).toBe(false);
  });

  it("keeps Confirm off until a code is typed [I4]", () => {
    const send = mount(true);
    const confirm = screen.getByRole<HTMLButtonElement>("button", { name: "Confirm" });
    expect(confirm.disabled).toBe(true);
    fireEvent.change(field(), { target: { value: "   " } });
    expect(confirm.disabled).toBe(true);
    fireEvent.click(confirm);
    expect(send).not.toHaveBeenCalled();
  });

  it("sends the typed code, trimmed, with the approve command [I4]", () => {
    const send = mount(true);
    fireEvent.change(field(), { target: { value: " K7Q2M9XA " } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    const command: unknown = send.mock.calls[0]?.[0];
    expect(CommandSchema.safeParse(command).success).toBe(true);
    expect(command).toEqual({
      type: "endorsement_decision",
      run_id: RUN_ID,
      endorsement_id: CARD,
      decision: "approve",
      code: "K7Q2M9XA",
    });
  });

  it("Reject needs no code and sends none [I4]", () => {
    const send = mount(true);
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    expect(send.mock.calls[0]?.[0]).toEqual({
      type: "endorsement_decision",
      run_id: RUN_ID,
      endorsement_id: CARD,
      decision: "reject",
    });
  });
});
